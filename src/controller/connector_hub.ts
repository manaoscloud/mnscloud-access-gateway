// Connector tunnels terminated by this gateway (`/access-gateway/<key>/connector`).
//
// Handshake (text messages, before any binary frame):
//   gateway -> {"t":"challenge","challenge":"<32 random bytes, base64url>"}
//   connector -> {"t":"hello","connectorUuid":"<uuid>","signature":"<base64url Ed25519>"}
//     signature over "mns-connector-tunnel-v1\n<gateway key>\n<challenge>"
//   gateway fetches the public key from the API (host Agent identity), verifies, calls attach
//   gateway -> {"t":"ready","maxStreams":<n>,"window":262144}
// Afterwards only binary frames (src/shared/tunnel.ts). One tunnel per connector: a newly
// authenticated tunnel replaces the old one. Only this side opens streams.

import { b64urlEncode, tunnelSigningString, verifyText } from '../shared/connector_auth.ts';
import {
  INITIAL_WINDOW,
  Mux,
  OpenError,
  type OpenSpec,
  type TunnelStream,
} from '../shared/tunnel.ts';
import { UUID } from './contract.ts';

export interface ConnectorRuntimeApi {
  connector(uuid: string): Promise<{ publicKey: string } | null>;
  connectorAttach(uuid: string): Promise<void>;
  connectorDetach(uuid: string): Promise<void>;
}

/** The part of a WebSocket the hub uses (a fake in tests). */
export interface HubSocket {
  readyState: number;
  binaryType: string;
  send(data: string | Uint8Array): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
}

export interface HubOptions {
  gatewayKey: string;
  api: ConnectorRuntimeApi;
  /** Current capacity of the gateway (maximum streams per tunnel). */
  maxStreams(): number;
  log(message: string): void;
  handshakeTimeoutMs?: number;
}

interface Tunnel {
  uuid: string;
  socket: HubSocket;
  mux: Mux;
}

const MAX_PENDING_HANDSHAKES = 32;
const MAX_HELLO_BYTES = 1024;

export class ConnectorHub {
  readonly tunnels = new Map<string, Tunnel>();
  #pending = 0;
  #draining = false;

  constructor(private readonly options: HubOptions) {}

  get connected() {
    return this.tunnels.size;
  }

  has(connectorUuid: string): boolean {
    return this.tunnels.has(connectorUuid);
  }

  /** HTTP side: upgrades the request and runs the handshake. */
  handleUpgrade(request: Request): Response {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('WebSocket required', { status: 426 });
    }
    if (this.#draining || this.#pending >= MAX_PENDING_HANDSHAKES) {
      return new Response('Busy', { status: 503 });
    }
    const { socket, response } = Deno.upgradeWebSocket(request, { idleTimeout: 60 });
    this.attach(socket as unknown as HubSocket);
    return response;
  }

  /** Runs the handshake and then the multiplexer on one accepted socket. */
  attach(socket: HubSocket) {
    socket.binaryType = 'arraybuffer';
    const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    let state: 'hello' | 'verifying' | 'ready' | 'closed' = 'hello';
    let tunnel: Tunnel | null = null;
    const isClosed = () => state === 'closed';
    this.#pending++;
    let counted = true;
    const settle = () => {
      if (counted) {
        counted = false;
        this.#pending--;
      }
    };
    const timer = setTimeout(() => {
      if (state !== 'ready') fail(4408, 'handshake_timeout');
    }, this.options.handshakeTimeoutMs ?? 10000);

    const fail = (code: number, reason: string) => {
      if (state === 'closed') return;
      state = 'closed';
      clearTimeout(timer);
      settle();
      try {
        socket.close(code, reason);
      } catch { /* closed */ }
      if (tunnel) this.#drop(tunnel);
    };

    const sendHello = () => {
      try {
        socket.send(JSON.stringify({ t: 'challenge', challenge }));
      } catch {
        fail(4500, 'send_failed');
      }
    };
    if (socket.readyState === 1) sendHello();
    else socket.onopen = () => sendHello();

    socket.onclose = () => {
      state = 'closed';
      clearTimeout(timer);
      settle();
      if (tunnel) this.#drop(tunnel);
    };
    socket.onerror = () => fail(4500, 'socket_error');
    socket.onmessage = (event) => {
      if (state === 'closed') return;
      if (state === 'ready') {
        if (typeof event.data === 'string' || !tunnel) return fail(4400, 'protocol_error');
        tunnel.mux.receive(new Uint8Array(event.data as ArrayBuffer));
        return;
      }
      if (state === 'verifying' || typeof event.data !== 'string') {
        return fail(4400, 'protocol_error');
      }
      state = 'verifying';
      void this.#verify(event.data, challenge).then(async (uuid) => {
        if (isClosed()) return;
        if (!uuid) return fail(4401, 'unauthorized');
        const candidate = this.#buildTunnel(uuid, socket, fail);
        try {
          await this.options.api.connectorAttach(uuid);
        } catch (error) {
          this.options.log(`connector attach refused: ${(error as Error).message}`);
          candidate.mux.close('attach_failed');
          return fail(4503, 'attach_failed');
        }
        if (isClosed()) {
          await this.options.api.connectorDetach(uuid).catch(() => {});
          return;
        }
        const previous = this.tunnels.get(uuid);
        this.tunnels.set(uuid, candidate);
        if (previous) {
          this.#closeTunnel(previous, 4409, 'replaced');
        }
        tunnel = candidate;
        state = 'ready';
        clearTimeout(timer);
        settle();
        socket.send(JSON.stringify({
          t: 'ready',
          maxStreams: this.options.maxStreams(),
          window: INITIAL_WINDOW,
        }));
        candidate.mux.startKeepalive();
      }).catch(() => fail(4401, 'unauthorized'));
    };
  }

  #buildTunnel(
    uuid: string,
    socket: HubSocket,
    fail: (code: number, reason: string) => void,
  ): Tunnel {
    const mux = new Mux({
      role: 'gateway',
      send: (bytes) => socket.send(bytes),
      onFatal: (reason) => fail(4400, reason.slice(0, 100)),
      maxStreams: this.options.maxStreams(),
    });
    return { uuid, socket, mux };
  }

  async #verify(raw: string, challenge: string): Promise<string | null> {
    if (raw.length > MAX_HELLO_BYTES) return null;
    let hello: { t?: unknown; connectorUuid?: unknown; signature?: unknown };
    try {
      hello = JSON.parse(raw);
    } catch {
      return null;
    }
    if (
      hello?.t !== 'hello' || typeof hello.connectorUuid !== 'string' ||
      !UUID.test(hello.connectorUuid) || typeof hello.signature !== 'string' ||
      hello.signature.length > 128
    ) return null;
    let record: { publicKey: string } | null;
    try {
      record = await this.options.api.connector(hello.connectorUuid);
    } catch {
      return null;
    }
    if (!record) return null;
    const ok = await verifyText(
      record.publicKey,
      tunnelSigningString(this.options.gatewayKey, challenge),
      hello.signature,
    );
    return ok ? hello.connectorUuid : null;
  }

  /** A tunnel ended (closed socket or protocol failure): detach it unless it was replaced. */
  #drop(tunnel: Tunnel) {
    tunnel.mux.close('tunnel_closed');
    if (this.tunnels.get(tunnel.uuid) !== tunnel) return;
    this.tunnels.delete(tunnel.uuid);
    void this.options.api.connectorDetach(tunnel.uuid).catch((error) =>
      this.options.log(`connector detach failed: ${(error as Error).message}`)
    );
  }

  #closeTunnel(tunnel: Tunnel, code: number, reason: string) {
    tunnel.mux.close(reason);
    try {
      tunnel.socket.close(code, reason);
    } catch { /* closed */ }
  }

  /** Opens one stream to `host:port` through the connector's tunnel. */
  async open(connectorUuid: string, spec: OpenSpec): Promise<TunnelStream> {
    const tunnel = this.tunnels.get(connectorUuid);
    if (!tunnel) throw new OpenError('connector_offline');
    return await tunnel.mux.open(spec);
  }

  /** Gateway shutdown: close every tunnel and detach. */
  async drain() {
    this.#draining = true;
    const tunnels = [...this.tunnels.values()];
    this.tunnels.clear();
    await Promise.all(tunnels.map(async (tunnel) => {
      this.#closeTunnel(tunnel, 4503, 'gateway_shutdown');
      await this.options.api.connectorDetach(tunnel.uuid).catch(() => {});
    }));
  }
}
