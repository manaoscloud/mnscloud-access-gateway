// Outbound tunnel of the connector to its assigned gateway (see src/controller/connector_hub.ts for
// the handshake). The connector never listens: it dials `wss://.../access-gateway/<key>/connector`
// (outbound HTTPS 443), proves its identity by signing the gateway's challenge and then only
// answers streams the gateway opens.

import { signText, tunnelSigningString } from '../shared/connector_auth.ts';
import { Mux, type OpenSpec } from '../shared/tunnel.ts';

export const MAX_CONNECTOR_STREAMS = 64;

export interface TunnelOptions {
  relayUrl: string;
  gatewayKey: string;
  connectorUuid: string;
  key: CryptoKey;
  onOpen(mux: Mux, id: number, spec: OpenSpec): void;
  log(message: string): void;
  /** Called once the gateway answered "ready" (the tunnel is usable). */
  onReady?(): void;
  handshakeTimeoutMs?: number;
}

/** Runs one tunnel until it closes. Resolves with whether it ever became ready. */
export function runTunnel(options: TunnelOptions, signal: AbortSignal): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = new WebSocket(options.relayUrl);
    socket.binaryType = 'arraybuffer';
    let mux: Mux | null = null;
    let ready = false;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      mux?.close('tunnel_closed');
      try {
        socket.close(1000, 'closing');
      } catch { /* closed */ }
      resolve(ready);
    };
    const onAbort = () => finish();
    signal.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => {
      if (!ready) {
        options.log('tunnel handshake timed out');
        finish();
      }
    }, options.handshakeTimeoutMs ?? 15000);
    if (signal.aborted) return finish();

    socket.onerror = () => finish();
    socket.onclose = () => finish();
    socket.onmessage = (event) => {
      if (ready) {
        if (typeof event.data === 'string') return finish();
        mux?.receive(new Uint8Array(event.data as ArrayBuffer));
        return;
      }
      if (typeof event.data !== 'string') return finish();
      let message: { t?: unknown; challenge?: unknown };
      try {
        message = JSON.parse(event.data);
      } catch {
        return finish();
      }
      if (message.t === 'challenge' && typeof message.challenge === 'string') {
        if (!/^[A-Za-z0-9_-]{43}$/.test(message.challenge)) return finish();
        // The signature binds the key of the gateway we meant to reach, not what the peer claims.
        signText(options.key, tunnelSigningString(options.gatewayKey, message.challenge))
          .then((signature) =>
            socket.send(JSON.stringify({
              t: 'hello',
              connectorUuid: options.connectorUuid,
              signature,
            }))
          ).catch(() => finish());
      } else if (message.t === 'ready') {
        ready = true;
        mux = new Mux({
          role: 'connector',
          send: (bytes) => socket.send(bytes),
          bufferedAmount: () => socket.bufferedAmount,
          onFatal: (reason) => {
            options.log(`tunnel protocol error: ${reason}`);
            finish();
          },
          maxStreams: MAX_CONNECTOR_STREAMS,
          onOpen: (id, spec) => options.onOpen(mux!, id, spec),
        });
        mux.startKeepalive();
        options.onReady?.();
      } else finish();
    };
  });
}

/** Backoff (ms) after `failures` consecutive failures: 1 s doubling to 60 s, with jitter. */
export function backoffMs(failures: number, random = Math.random): number {
  const base = Math.min(60000, 1000 * 2 ** Math.max(0, failures - 1));
  return Math.floor(base * (0.75 + random() * 0.5));
}
