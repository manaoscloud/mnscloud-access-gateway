// OPEN handling of the connector. The gateway asked for a stream to one destination; before any
// socket is opened the connector (1) validates the destination locally (loopback, link-local,
// multicast, own addresses, tenant allowed networks, Telnet/plain API ports), (2) asks the API to
// confirm that exact connection (single use) and only then (3) dials with a 10 s timeout.
// Any refusal answers OPEN_FAIL with a short code; nothing is dialed.

import { UUID } from '../controller/contract.ts';
import { checkConnectorDestination, type DestinationPolicy } from '../shared/destination.ts';
import { type Mux, type OpenSpec, type TunnelStream } from '../shared/tunnel.ts';

export const CONNECT_TIMEOUT_MS = 10000;
/** accept + connect (8 s + 10 s) stay under the gateway's 20 s open timeout. */
export const ACCEPT_TIMEOUT_MS = 8000;

export interface OpenDeps {
  /** Current policy (tenant allowed networks and this host's addresses). */
  policy(): DestinationPolicy;
  /** True when the API accepted this connection; throws or returns false otherwise. */
  accept(
    connectionUuid: string,
    host: string,
    port: number,
    signal: AbortSignal,
  ): Promise<boolean>;
  connect(
    host: string,
    port: number,
    timeoutMs: number,
    signal: AbortSignal,
  ): Promise<Deno.Conn>;
  log(message: string): void;
}

export async function dialWithTimeout(
  host: string,
  port: number,
  timeoutMs = CONNECT_TIMEOUT_MS,
  cancel?: AbortSignal,
): Promise<Deno.Conn> {
  const signal = cancel
    ? AbortSignal.any([AbortSignal.timeout(timeoutMs), cancel])
    : AbortSignal.timeout(timeoutMs);
  const connection = Deno.connect({ hostname: host, port, transport: 'tcp' });
  const timeout = new Promise<never>((_, reject) => {
    signal.addEventListener(
      'abort',
      () => reject(new Error(cancel?.aborted ? 'cancelled' : 'connect_timeout')),
      { once: true },
    );
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
      const chunk = await stream.read(); // NOSONAR: sequential pipe
      if (chunk === null) break;
      await conn.write(chunk); // NOSONAR: sequential pipe
    }
  })();
  const toGateway = (async () => {
    const buffer = new Uint8Array(32 * 1024);
    for (;;) {
      const n = await conn.read(buffer); // NOSONAR: sequential pipe
      if (n === null) break;
      await stream.write(buffer.slice(0, n)); // NOSONAR: sequential pipe
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

/** Asks the API to confirm the connection; returns a refusal code, or null when confirmed. */
async function confirm(
  spec: OpenSpec,
  deps: OpenDeps,
  signal: AbortSignal,
): Promise<string | null> {
  try {
    const accepted = await deps.accept(
      spec.connectionUuid,
      spec.host,
      spec.port,
      AbortSignal.any([signal, AbortSignal.timeout(ACCEPT_TIMEOUT_MS)]),
    );
    return accepted ? null : 'api_refused';
  } catch (error) {
    const status = (error as { status?: number }).status;
    const client = typeof status === 'number' && status >= 400 && status < 500 && status !== 429;
    return client ? 'api_refused' : 'api_unavailable';
  }
}

/** Dials the device; returns the connection or a refusal code. */
async function dial(
  spec: OpenSpec,
  deps: OpenDeps,
  signal: AbortSignal,
): Promise<Deno.Conn | string> {
  try {
    return await deps.connect(spec.host, spec.port, CONNECT_TIMEOUT_MS, signal);
  } catch (error) {
    return (error as Error).message === 'connect_timeout' ? 'connect_timeout' : 'connect_failed';
  }
}

export async function handleOpen(mux: Mux, id: number, spec: OpenSpec, deps: OpenDeps) {
  const refuse = (code: string) => {
    deps.log(`stream ${id} refused: ${code}`);
    mux.rejectOpen(id, code);
  };
  // Aborted when the gateway gave up (CLOSE) or the tunnel died: nothing may stay open for it.
  const signal = mux.openSignal(id);
  if (!signal) return;
  const early = UUID.test(spec.connectionUuid)
    ? checkConnectorDestination(spec.host, spec.port, deps.policy())
    : 'invalid_open';
  if (early) return refuse(early);
  const refused = await confirm(spec, deps, signal);
  if (signal.aborted) return;
  if (refused) return refuse(refused);
  const dialed = await dial(spec, deps, signal);
  if (signal.aborted || typeof dialed === 'string') {
    if (typeof dialed === 'string') {
      if (!signal.aborted) refuse(dialed);
    } else closeQuietly(dialed); // the gateway gave up while we were dialing
    return;
  }
  const stream = mux.acceptOpen(id);
  if (!stream) return closeQuietly(dialed);
  await pipe(dialed, stream);
}

function closeQuietly(conn: Deno.Conn) {
  try {
    conn.close();
  } catch { /* closed */ }
}
