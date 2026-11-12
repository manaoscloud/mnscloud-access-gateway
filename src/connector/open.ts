// OPEN handling of the connector. The gateway asked for a stream to one destination; before any
// socket is opened the connector (1) validates the destination locally (loopback, link-local,
// multicast, own addresses, tenant allowed networks, Telnet/plain API ports), (2) asks the API to
// confirm that exact connection (single use) and only then (3) dials with a 10 s timeout.
// Any refusal answers OPEN_FAIL with a short code; nothing is dialed.

import { UUID } from '../controller/contract.ts';
import { checkConnectorDestination, type DestinationPolicy } from '../shared/destination.ts';
import { type Mux, type OpenSpec, type TunnelStream } from '../shared/tunnel.ts';

export const CONNECT_TIMEOUT_MS = 10000;

export interface OpenDeps {
  /** Current policy (tenant allowed networks and this host's addresses). */
  policy(): DestinationPolicy;
  /** True when the API accepted this connection; throws or returns false otherwise. */
  accept(connectionUuid: string, host: string, port: number): Promise<boolean>;
  connect(host: string, port: number, timeoutMs: number): Promise<Deno.Conn>;
  log(message: string): void;
}

export async function dialWithTimeout(
  host: string,
  port: number,
  timeoutMs = CONNECT_TIMEOUT_MS,
): Promise<Deno.Conn> {
  const signal = AbortSignal.timeout(timeoutMs);
  const connection = Deno.connect({ hostname: host, port, transport: 'tcp' });
  const timeout = new Promise<never>((_, reject) => {
    signal.addEventListener('abort', () => reject(new Error('connect_timeout')), { once: true });
  });
  try {
    return await Promise.race([connection, timeout]);
  } catch (error) {
    // A late connection must not leak.
    connection.then((late) => late.close()).catch(() => {});
    throw error;
  }
}

/** Pipes the TCP connection and the stream both ways until either ends. */
export async function pipe(conn: Deno.Conn, stream: TunnelStream) {
  const toDevice = (async () => {
    for (;;) {
      const chunk = await stream.read();
      if (chunk === null) break;
      await conn.write(chunk);
    }
  })();
  const toGateway = (async () => {
    const buffer = new Uint8Array(32 * 1024);
    for (;;) {
      const n = await conn.read(buffer);
      if (n === null) break;
      await stream.write(buffer.slice(0, n));
    }
  })();
  try {
    await Promise.race([toDevice, toGateway]);
  } catch { /* one side went away */ }
  try {
    conn.close();
  } catch { /* closed */ }
  stream.close();
}

export async function handleOpen(mux: Mux, id: number, spec: OpenSpec, deps: OpenDeps) {
  const refuse = (code: string) => {
    deps.log(`stream ${id} refused: ${code}`);
    mux.rejectOpen(id, code);
  };
  if (!UUID.test(spec.connectionUuid)) return refuse('invalid_open');
  const verdict = checkConnectorDestination(spec.host, spec.port, deps.policy());
  if (verdict) return refuse(verdict);
  try {
    if (!(await deps.accept(spec.connectionUuid, spec.host, spec.port))) {
      return refuse('api_refused');
    }
  } catch (error) {
    const status = (error as { status?: number }).status;
    return refuse(
      typeof status === 'number' && status >= 400 && status < 500 && status !== 429
        ? 'api_refused'
        : 'api_unavailable',
    );
  }
  let conn: Deno.Conn;
  try {
    conn = await deps.connect(spec.host, spec.port, CONNECT_TIMEOUT_MS);
  } catch (error) {
    return refuse(
      (error as Error).message === 'connect_timeout' ? 'connect_timeout' : 'connect_failed',
    );
  }
  const stream = mux.acceptOpen(id);
  await pipe(conn, stream);
}
