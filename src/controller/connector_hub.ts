// Connector tunnels terminated by this gateway (`/access-gateway/<key>/connector`).
//
// Handshake (text messages, before any binary frame):
//   gateway -> {"t":"challenge","challenge":"<32 random bytes, base64url>"}
//   connector -> {"t":"hello","connectorUuid":"<uuid>","signature":"<base64url Ed25519>"}
//     signature over "mns-connector-tunnel-v1\n<gateway key>\n<challenge>"
//   gateway fetches the public key from the API (host Agent identity), verifies, calls attach
//   gateway -> {"t":"ready","maxStreams":<n>,"window":262144}
// Afterwards only binary frames (src/shared/tunnel.ts). One tunnel per connector: a newly
// authenticated tunnel replaces the old one. Only this side opens streams. The verified public key
// is kept with the tunnel and re-checked every minute: a disabled, deleted or re-installed
// connector loses its tunnel.

import {
  b64urlEncode,
  publicKeyFingerprint,
  tunnelSigningString,
  verifyText,
} from '../shared/connector_auth.ts';
import { parseAddress } from '../shared/ip.ts';
import {
  INITIAL_WINDOW,
  Mux,
  OpenError,
  type OpenSpec,
  type TunnelStream,
} from '../shared/tunnel.ts';
import { UUID } from './contract.ts';

/** The API refused an attach for good (disabled, deleted or re-installed connector). */
export class AttachRefused extends Error {}

/** Where the API records the connector's tunnel: this gateway, none or another gateway. */
export type ConnectorAttachment = 'here' | 'none' | 'other';

export interface ConnectorRuntimeApi {
  connector(uuid: string): Promise<{ publicKey: string; attachment?: ConnectorAttachment } | null>;
  connectorAttach(uuid: string): Promise<void>;
  connectorDetach(uuid: string): Promise<void>;
}

/** The part of a WebSocket the hub uses (a fake in tests). */
export interface HubSocket {
  readyState: number;
  binaryType: string;
  bufferedAmount?: number;
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
  /** Time an unauthenticated socket may take to present a valid hello (default 3 s). */
  handshakeTimeoutMs?: number;
  /** How often an attached tunnel's key is verified again (default 60 s). */
  recheckMs?: number;
}

interface Tunnel {
  uuid: string;
  socket: HubSocket;
  mux: Mux;
  publicKey: string;
  fingerprint: string;
  recheck: ReturnType<typeof setInterval> | null;
}

const MAX_PENDING_HANDSHAKES = 32;
const MAX_PENDING_PER_SOURCE = 4;
const MAX_KEY_LOOKUPS = 8;
const MAX_HELLO_BYTES = 1024;

/**
 * Client address the trusted edge saw: `X-Real-IP`, else the last `X-Forwarded-For` entry (the one
 * the edge appended), else the socket peer. Only called for requests that already passed the
 * edge-source check, so the headers come from our own nginx.
 */
export function sourceOf(request: Request, remote: string): string {
  const real = request.headers.get('x-real-ip')?.trim();
  if (real && parseAddress(real)) return parseAddress(real)!.text;
  const forwarded = request.headers.get('x-forwarded-for')?.split(',').at(-1)?.trim();
  if (forwarded && parseAddress(forwarded)) return parseAddress(forwarded)!.text;
  return remote;
}

export class ConnectorHub {
  readonly tunnels = new Map<string, Tunnel>();
  #pending = 0;
  #lookups = 0;
  readonly #bySource = new Map<string, number>();
  readonly #chains = new Map<string, Promise<void>>();
  #draining = false;

  constructor(private readonly options: HubOptions) {}

  get connected() {
    return this.tunnels.size;
  }

  has(connectorUuid: string): boolean {
    return this.tunnels.has(connectorUuid);
  }

  /** Fingerprint of the key the attached tunnel authenticated with. */
  fingerprintOf(connectorUuid: string): string | null {
    return this.tunnels.get(connectorUuid)?.fingerprint ?? null;
  }

  /** HTTP side: upgrades the request and runs the handshake. */
  handleUpgrade(request: Request, remote = 'unknown'): Response {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('WebSocket required', { status: 426 });
    }
    const source = sourceOf(request, remote);
    if (
      this.#draining || this.#pending >= MAX_PENDING_HANDSHAKES ||
      (this.#bySource.get(source) ?? 0) >= MAX_PENDING_PER_SOURCE
    ) {
      return new Response('Busy', { status: 503 });
    }
    const { socket, response } = Deno.upgradeWebSocket(request, { idleTimeout: 60 });
    this.attach(socket as unknown as HubSocket, source);
    return response;
  }

  /** Serializes API attach/detach calls of one connector. */
  #serial<T>(uuid: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.#chains.get(uuid) ?? Promise.resolve();
    const run = previous.then(fn, fn);
    const tail = run.then(() => {}, () => {});
    this.#chains.set(uuid, tail);
    void tail.then(() => {
      if (this.#chains.get(uuid) === tail) this.#chains.delete(uuid);
    });
    return run;
  }

  /** Runs the handshake and then the multiplexer on one accepted socket. */
  attach(socket: HubSocket, source = 'unknown') {
    socket.binaryType = 'arraybuffer';
    const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    let state: 'hello' | 'verifying' | 'ready' | 'closed' = 'hello';
    const isClosed = () => state === 'closed';
    let tunnel: Tunnel | null = null;
    this.#pending++;
    this.#bySource.set(source, (this.#bySource.get(source) ?? 0) + 1);
    let counted = true;
    const settle = () => {
      if (!counted) return;
      counted = false;
      this.#pending--;
      const left = (this.#bySource.get(source) ?? 1) - 1;
      if (left <= 0) this.#bySource.delete(source);
      else this.#bySource.set(source, left);
    };
    const timer = setTimeout(() => {
      if (state !== 'ready') fail(4408, 'handshake_timeout');
    }, this.options.handshakeTimeoutMs ?? 3000);

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

    const sendChallenge = () => {
      try {
        socket.send(JSON.stringify({ t: 'challenge', challenge }));
      } catch {
        fail(4500, 'send_failed');
      }
    };
    if (socket.readyState === 1) sendChallenge();
    else socket.onopen = () => sendChallenge();

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
      void this.#verify(event.data, challenge).then(async (verified) => {
        if (isClosed()) return;
        if (verified === 'busy') return fail(4429, 'busy');
        if (!verified) return fail(4401, 'unauthorized');
        const candidate = this.#buildTunnel(verified, socket, fail);
        try {
          await this.#serial(verified.uuid, async () => {
            await this.options.api.connectorAttach(verified.uuid);
            if (isClosed()) return;
            const previous = this.tunnels.get(verified.uuid);
            this.tunnels.set(verified.uuid, candidate);
            if (previous) this.#closeTunnel(previous, 4409, 'replaced');
          });
        } catch (error) {
          this.options.log(`connector attach refused: ${(error as Error).message}`);
          candidate.mux.close('attach_failed');
          return fail(4503, 'attach_failed');
        }
        if (isClosed()) {
          this.#detachIfAbsent(verified.uuid);
          return;
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
        candidate.recheck = setInterval(
          () => void this.#recheck(candidate, fail),
          this.options.recheckMs ?? 60000,
        );
      }).catch(() => fail(4401, 'unauthorized'));
    };
  }

  #buildTunnel(
    verified: { uuid: string; publicKey: string; fingerprint: string },
    socket: HubSocket,
    fail: (code: number, reason: string) => void,
  ): Tunnel {
    const mux = new Mux({
      role: 'gateway',
      send: (bytes) => socket.send(bytes),
      bufferedAmount: () => socket.bufferedAmount ?? 0,
      onFatal: (reason) => fail(4400, reason.slice(0, 100)),
      maxStreams: this.options.maxStreams(),
    });
    return { ...verified, socket, mux, recheck: null };
  }

  /**
   * The key of an attached tunnel must still be the connector's current, active key, and the API must
   * still record the tunnel here: a disable/enable (or a reinstall race) can clear the record while the
   * socket stays up, which would leave a live tunnel that consoles cannot use. 'none' attaches again,
   * 'other' means another gateway holds the connector now.
   */
  async #recheck(tunnel: Tunnel, fail: (code: number, reason: string) => void) {
    let record: { publicKey: string; attachment?: ConnectorAttachment } | null;
    try {
      record = await this.options.api.connector(tunnel.uuid);
    } catch {
      return; // transient API failure: keep the tunnel, the next check decides
    }
    if (this.tunnels.get(tunnel.uuid) !== tunnel) return;
    if (record?.publicKey !== tunnel.publicKey) {
      this.options.log('connector key no longer valid: closing its tunnel');
      return fail(4401, 'key_changed');
    }
    if (record.attachment === 'other') {
      this.options.log('connector is attached to another gateway: closing its tunnel');
      return fail(4409, 'replaced');
    }
    if (record.attachment !== 'none') return;
    try {
      await this.#serial(tunnel.uuid, async () => {
        if (this.tunnels.get(tunnel.uuid) === tunnel) {
          await this.options.api.connectorAttach(tunnel.uuid);
        }
      });
      this.options.log('connector tunnel attached again');
    } catch (error) {
      if (error instanceof AttachRefused) {
        this.options.log(`connector attach refused: ${error.message}`);
        if (this.tunnels.get(tunnel.uuid) === tunnel) fail(4503, 'attach_failed');
      } // a transient failure keeps the tunnel; the next check tries again
    }
  }

  async #verify(
    raw: string,
    challenge: string,
  ): Promise<{ uuid: string; publicKey: string; fingerprint: string } | 'busy' | null> {
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
    // Bounded key lookups: unauthenticated sockets cannot flood the API.
    if (this.#lookups >= MAX_KEY_LOOKUPS) return 'busy';
    this.#lookups++;
    let record: { publicKey: string } | null;
    try {
      record = await this.options.api.connector(hello.connectorUuid);
    } catch {
      return null;
    } finally {
      this.#lookups--;
    }
    if (!record) return null;
    const ok = await verifyText(
      record.publicKey,
      tunnelSigningString(this.options.gatewayKey, challenge),
      hello.signature,
    );
    if (!ok) return null;
    return {
      uuid: hello.connectorUuid,
      publicKey: record.publicKey,
      fingerprint: await publicKeyFingerprint(record.publicKey),
    };
  }

  /** A tunnel ended (closed socket or protocol failure): detach it unless it was replaced. */
  #drop(tunnel: Tunnel) {
    if (tunnel.recheck) clearInterval(tunnel.recheck);
    tunnel.mux.close('tunnel_closed');
    if (this.tunnels.get(tunnel.uuid) !== tunnel) return;
    this.tunnels.delete(tunnel.uuid);
    this.#detachIfAbsent(tunnel.uuid);
  }

  /** Detaches only when, at the moment it runs, no tunnel of that connector is attached. */
  #detachIfAbsent(uuid: string) {
    void this.#serial(uuid, async () => {
      if (this.tunnels.has(uuid)) return;
      await this.options.api.connectorDetach(uuid);
    }).catch((error) => this.options.log(`connector detach failed: ${(error as Error).message}`));
  }

  #closeTunnel(tunnel: Tunnel, code: number, reason: string) {
    if (tunnel.recheck) clearInterval(tunnel.recheck);
    tunnel.mux.close(reason);
    try {
      tunnel.socket.close(code, reason);
    } catch { /* closed */ }
  }

  /**
   * Opens one stream to `host:port` through the connector's tunnel. `fingerprint` is the key
   * fingerprint the API put in the assignment: a tunnel authenticated with another key is refused.
   */
  async open(
    connectorUuid: string,
    spec: OpenSpec,
    fingerprint?: string | null,
  ): Promise<TunnelStream> {
    const tunnel = this.tunnels.get(connectorUuid);
    if (!tunnel) throw new OpenError('connector_offline');
    if (fingerprint !== undefined && fingerprint !== tunnel.fingerprint) {
      throw new OpenError('connector_key_mismatch');
    }
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
