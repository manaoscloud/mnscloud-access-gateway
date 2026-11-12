// Unix-socket bridge between a connector tunnel stream and the sandboxed worker. The worker of a
// connector session has no network at all: it connects to this socket (the only thing its Deno
// permissions allow) and the controller pipes the bytes to the tunnel stream. The gateway never
// forwards packets: the stream ends inside the worker's own SSH/TLS client.

import type { TunnelStream } from '../shared/tunnel.ts';

export const BRIDGE_DIR = '/run/mnscloud-access-gateway-bridge';

export interface Bridge {
  /** Socket path of the bridge on the host. */
  path: string;
  /** Per-session secret the worker must present first (sent to it on stdin, never on argv). */
  secret: string;
  /** Closes the listener, the worker connection and the tunnel stream. */
  close(): void;
}

function randomHex(bytes: number): string {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(bytes)),
    (b) => b.toString(16).padStart(2, '0'),
  ).join('');
}

const SECRET_HEX = 64;
const MAX_CANDIDATES = 8;
const PEER_TIMEOUT_MS = 5000;
const BRIDGE_DEADLINE_MS = 60000;

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Reads the first 64 bytes of a candidate peer; returns them and anything read past them. */
async function readSecret(
  conn: Deno.Conn,
): Promise<{ secret: Uint8Array; rest: Uint8Array } | null> {
  const buffer = new Uint8Array(SECRET_HEX + 32 * 1024);
  let have = 0;
  const deadline = Date.now() + PEER_TIMEOUT_MS;
  while (have < SECRET_HEX) {
    const left = deadline - Date.now();
    if (left <= 0) return null;
    const n = await Promise.race([
      conn.read(buffer.subarray(have, have + 1024)),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), left)),
    ]);
    if (n === null) return null;
    have += n;
  }
  return { secret: buffer.slice(0, SECRET_HEX), rest: buffer.slice(SECRET_HEX, have) };
}

export async function startBridge(stream: TunnelStream, dir = BRIDGE_DIR): Promise<Bridge> {
  // 0711: the unguessable name below cannot be listed, only traversed by the worker's dynamic user.
  await Deno.mkdir(dir, { recursive: true, mode: 0o711 });
  const path = `${dir}/${randomHex(16)}.sock`;
  const secret = randomHex(SECRET_HEX / 2);
  const expected = new TextEncoder().encode(secret);
  const listener = Deno.listen({ transport: 'unix', path });
  await Deno.chmod(path, 0o666); // NOSONAR: world-connectable by design (worker is a dynamic user); only the session secret is accepted
  let connection: Deno.Conn | null = null;
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    clearTimeout(deadline);
    try {
      listener.close();
    } catch { /* closed */ }
    try {
      connection?.close();
    } catch { /* closed */ }
    stream.close();
    Deno.remove(path).catch(() => {});
  };
  // Nobody proved the secret in time: the connection is abandoned.
  const deadline = setTimeout(() => {
    if (!connection) close();
  }, BRIDGE_DEADLINE_MS);

  void (async () => {
    try {
      // Other local processes may reach the socket (a compromised worker of another session): only
      // the peer that presents this session's secret is bridged, the others are dropped.
      let conn: Deno.Conn | null = null;
      let rest: Uint8Array = new Uint8Array(0);
      for (let attempt = 0; attempt < MAX_CANDIDATES && !conn && !closed; attempt++) {
        const candidate = await listener.accept(); // NOSONAR: sequential
        const read = await readSecret(candidate).catch(() => null); // NOSONAR: sequential
        if (read && sameBytes(read.secret, expected)) {
          conn = candidate;
          rest = read.rest;
        } else {
          try {
            candidate.close();
          } catch { /* closed */ }
        }
      }
      if (!conn) return close();
      connection = conn;
      clearTimeout(deadline);
      listener.close();
      Deno.remove(path).catch(() => {});
      const peer = conn;
      const toWorker = (async () => {
        for (;;) {
          const chunk = await stream.read(); // NOSONAR: sequential
          if (chunk === null) break;
          await peer.write(chunk); // NOSONAR: sequential
        }
      })();
      const toDevice = (async () => {
        if (rest.length) await stream.write(rest);
        const buffer = new Uint8Array(32 * 1024);
        for (;;) {
          const n = await peer.read(buffer); // NOSONAR: sequential
          if (n === null) break;
          await stream.write(buffer.slice(0, n)); // NOSONAR: sequential
        }
      })();
      await Promise.race([toWorker, toDevice]);
    } catch { /* the other end went away */ }
    close();
  })();
  return { path, secret, close };
}
