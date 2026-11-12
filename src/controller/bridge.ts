// Unix-socket bridge between a connector tunnel stream and the sandboxed worker. The worker of a
// connector session has no network at all: it connects to this socket (the only thing its Deno
// permissions allow) and the controller pipes the bytes to the tunnel stream. The gateway never
// forwards packets: the stream ends inside the worker's own SSH/TLS client.

import type { TunnelStream } from '../shared/tunnel.ts';

export const BRIDGE_DIR = '/run/mnscloud-access-gateway-bridge';

export interface Bridge {
  /** Socket path handed to the worker. */
  path: string;
  /** Closes the listener, the worker connection and the tunnel stream. */
  close(): void;
}

function randomHex(bytes: number): string {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(bytes)),
    (b) => b.toString(16).padStart(2, '0'),
  )
    .join('');
}

export async function startBridge(stream: TunnelStream, dir = BRIDGE_DIR): Promise<Bridge> {
  // 0711: the unguessable name below cannot be listed, only traversed by the worker's dynamic user.
  await Deno.mkdir(dir, { recursive: true, mode: 0o711 });
  const path = `${dir}/${randomHex(16)}.sock`;
  const listener = Deno.listen({ transport: 'unix', path });
  await Deno.chmod(path, 0o666);
  let connection: Deno.Conn | null = null;
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    try {
      listener.close();
    } catch { /* closed */ }
    try {
      connection?.close();
    } catch { /* closed */ }
    stream.close();
    Deno.remove(path).catch(() => {});
  };

  void (async () => {
    try {
      // One connection only: the worker. The listener is closed as soon as it arrived.
      connection = await listener.accept();
      listener.close();
      Deno.remove(path).catch(() => {});
      const conn = connection;
      const toWorker = (async () => {
        for (;;) {
          const chunk = await stream.read();
          if (chunk === null) break;
          await conn.write(chunk);
        }
      })();
      const toDevice = (async () => {
        const buffer = new Uint8Array(32 * 1024);
        for (;;) {
          const n = await conn.read(buffer);
          if (n === null) break;
          await stream.write(buffer.slice(0, n));
        }
      })();
      await Promise.race([toWorker, toDevice]);
    } catch { /* the other end went away */ }
    close();
  })();
  return { path, close };
}
