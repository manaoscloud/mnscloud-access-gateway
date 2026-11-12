// Tunnel frame codec and multiplexer: OPEN only from the gateway, CREDIT flow control, limits,
// keepalive.

import {
  creditPayload,
  DATA_CHUNK_BYTES,
  decodeFrame,
  encodeFrame,
  FrameType,
  INITIAL_WINDOW,
  MAX_FRAME_BYTES,
  Mux,
  OpenError,
  type OpenSpec,
  TunnelProtocolError,
  type TunnelStream,
} from '../src/shared/tunnel.ts';
import { assert, assertEquals, assertRejects, assertThrows } from './assert.ts';

const SPEC: OpenSpec = {
  connectionUuid: '0b793486-b265-4564-9bfd-df227704d8f9',
  host: '10.20.30.40',
  port: 22,
};

interface Pair {
  gateway: Mux;
  connector: Mux;
  fatal: { gateway: string[]; connector: string[] };
  opens: { id: number; spec: OpenSpec }[];
  /** Frames the gateway sent (decoded types) for flow-control assertions. */
  wire: { from: 'gateway' | 'connector'; type: number; stream: number; size: number }[];
}

function pair(
  options: { maxStreams?: number; autoAccept?: boolean; now?: () => number } = {},
): Pair {
  const fatal = { gateway: [] as string[], connector: [] as string[] };
  const opens: Pair['opens'] = [];
  const wire: Pair['wire'] = [];
  // deno-lint-ignore prefer-const
  let connector: Mux;
  // deno-lint-ignore prefer-const
  let gateway: Mux;
  const deliver = (from: 'gateway' | 'connector', to: () => Mux) => (bytes: Uint8Array) => {
    const frame = decodeFrame(bytes);
    wire.push({ from, type: frame.type, stream: frame.stream, size: frame.payload.length });
    queueMicrotask(() => to().receive(bytes));
  };
  gateway = new Mux({
    role: 'gateway',
    send: deliver('gateway', () => connector),
    onFatal: (r) => fatal.gateway.push(r),
    maxStreams: options.maxStreams ?? 8,
    now: options.now,
  });
  connector = new Mux({
    role: 'connector',
    send: deliver('connector', () => gateway),
    onFatal: (r) => fatal.connector.push(r),
    maxStreams: options.maxStreams ?? 8,
    now: options.now,
    onOpen: (id, spec) => {
      opens.push({ id, spec });
      if (options.autoAccept !== false) connector.acceptOpen(id);
    },
  });
  return { gateway, connector, fatal, opens, wire };
}

const tick = () => new Promise((r) => setTimeout(r, 5));

Deno.test('tunnel: frame codec round trip and strict decoding', () => {
  const frame = decodeFrame(encodeFrame(FrameType.DATA, 0x01020304, Uint8Array.of(9, 8, 7)));
  assertEquals([frame.type, frame.stream, [...frame.payload]], [FrameType.DATA, 0x01020304, [
    9,
    8,
    7,
  ]]);
  assertEquals([...encodeFrame(FrameType.CLOSE, 258).subarray(0, 5)], [5, 0, 0, 1, 2]);
  assertThrows(() => decodeFrame(Uint8Array.of(4, 0, 0)), /short/);
  assertThrows(() => decodeFrame(Uint8Array.of(99, 0, 0, 0, 1)), /unknown/);
  assertThrows(() => decodeFrame(new Uint8Array(MAX_FRAME_BYTES + 1).fill(4, 0, 1)), /too large/);
  assertThrows(() => encodeFrame(FrameType.DATA, 1, new Uint8Array(MAX_FRAME_BYTES)), /too large/);
  assertEquals([...creditPayload(262144)], [0, 4, 0, 0]);
});

Deno.test('tunnel: only the gateway opens streams', async () => {
  const p = pair();
  const stream = await p.gateway.open(SPEC);
  assertEquals(p.opens[0].spec, SPEC);
  assert(stream.id >= 1);
  // A connector-side open is not even constructible.
  assertThrows(() => {
    void p.connector.open(SPEC);
  }, /only the gateway/);
});

Deno.test('tunnel: OPEN received by the gateway ends the tunnel', async () => {
  const p = pair();
  p.gateway.receive(encodeFrame(FrameType.OPEN, 7, new TextEncoder().encode(JSON.stringify(SPEC))));
  assertEquals(p.fatal.gateway, ['open from connector']);
  await assertRejects(() => p.gateway.open(SPEC), /tunnel_closed/);
});

Deno.test('tunnel: unknown type, oversized frame and wrong replies end the tunnel', () => {
  for (
    const bytes of [
      Uint8Array.of(0xee, 0, 0, 0, 1),
      Uint8Array.of(1, 0, 0), // short
      new Uint8Array(MAX_FRAME_BYTES + 1).fill(4, 0, 1),
    ]
  ) {
    const p = pair();
    p.gateway.receive(bytes);
    assertEquals(p.fatal.gateway.length, 1);
  }
  const p = pair();
  p.connector.receive(encodeFrame(FrameType.OPEN_OK, 1)); // connector never gets replies
  assertEquals(p.fatal.connector, ['unexpected open reply']);
});

Deno.test('tunnel: OPEN_FAIL carries the connector code', async () => {
  const p = pair({ autoAccept: false });
  const attempt = p.gateway.open(SPEC);
  await tick();
  p.connector.rejectOpen(p.opens[0].id, 'destination_refused');
  const error = await attempt.then(() => null, (e) => e);
  assert(error instanceof OpenError);
  assertEquals((error as OpenError).code, 'destination_refused');
});

Deno.test('tunnel: stream limit is enforced on both sides', async () => {
  const p = pair({ maxStreams: 2 });
  await p.gateway.open(SPEC);
  await p.gateway.open(SPEC);
  await assertRejects(() => p.gateway.open(SPEC), /too_many_streams/);
  // The connector refuses an OPEN above its own limit with OPEN_FAIL (the gateway never exceeds it).
  const q = pair({ maxStreams: 1 });
  await q.gateway.open(SPEC);
  q.connector.receive(
    encodeFrame(FrameType.OPEN, 99, new TextEncoder().encode(JSON.stringify(SPEC))),
  );
  assertEquals(q.wire.at(-1)?.type, FrameType.OPEN_FAIL);
});

Deno.test('tunnel: open timeout closes the pending stream', async () => {
  const p = pair({ autoAccept: false });
  await assertRejects(() => p.gateway.open(SPEC, 20), /open_timeout/);
});

async function drain(stream: TunnelStream, total: number): Promise<number> {
  let got = 0;
  while (got < total) {
    const chunk = await stream.read();
    if (chunk === null) break;
    got += chunk.length;
  }
  return got;
}

Deno.test('tunnel: CREDIT flow control stalls the sender until the reader consumes', async () => {
  const p = pair();
  const toConnector = await p.gateway.open(SPEC);
  const atConnector = p.connector.streams.get(toConnector.id)!;
  const payload = new Uint8Array(INITIAL_WINDOW + 100_000).fill(7);
  let written = false;
  const writing = toConnector.write(payload).then(() => (written = true));
  await tick();
  await tick();
  const sent = p.wire.filter((f) => f.from === 'gateway' && f.type === FrameType.DATA)
    .reduce((sum, f) => sum + f.size, 0);
  assertEquals(sent, INITIAL_WINDOW, 'sender stops at the window');
  assert(!written, 'writer is waiting for credit');
  assert(
    p.wire.every((f) =>
      f.size <= MAX_FRAME_BYTES - 5 && f.size <= DATA_CHUNK_BYTES || f.type !== FrameType.DATA
    ),
  );
  // The reader consumes: CREDIT frames flow back and the rest is sent.
  const reading = drain(atConnector, payload.length);
  await writing;
  assertEquals(await reading, payload.length);
  assert(p.wire.some((f) => f.from === 'connector' && f.type === FrameType.CREDIT));
  assertEquals(p.fatal.gateway.concat(p.fatal.connector), []);
});

Deno.test('tunnel: data beyond the granted window and credit overflow are violations', async () => {
  const p = pair();
  const stream = await p.gateway.open(SPEC);
  // Peer pretends to send more than the window in total.
  for (let i = 0; i < INITIAL_WINDOW / 16384; i++) {
    p.gateway.receive(encodeFrame(FrameType.DATA, stream.id, new Uint8Array(16384)));
  }
  assertEquals(p.fatal.gateway, []);
  p.gateway.receive(encodeFrame(FrameType.DATA, stream.id, new Uint8Array(1)));
  assertEquals(p.fatal.gateway, ['data beyond window']);
  const q = pair();
  const s = await q.gateway.open(SPEC);
  q.gateway.receive(encodeFrame(FrameType.CREDIT, s.id, creditPayload(1)));
  assertEquals(q.fatal.gateway, ['credit overflow']);
});

Deno.test('tunnel: CLOSE ends reads and writes; unknown streams are ignored', async () => {
  const p = pair();
  const stream = await p.gateway.open(SPEC);
  const atConnector = p.connector.streams.get(stream.id)!;
  await atConnector.write(Uint8Array.of(1, 2, 3));
  assertEquals([...(await stream.read())!], [1, 2, 3]);
  atConnector.close();
  await tick();
  assertEquals(await stream.read(), null);
  await assertRejects(() => stream.write(Uint8Array.of(1)), /closed/);
  p.gateway.receive(encodeFrame(FrameType.DATA, 4242, Uint8Array.of(1)));
  p.gateway.receive(encodeFrame(FrameType.CLOSE, 4242));
  assertEquals(p.fatal.gateway, []);
});

Deno.test('tunnel: idle ping after 20 s, dead after 60 s without frames', () => {
  let now = 1_000_000;
  const sent: number[] = [];
  const fatal: string[] = [];
  const mux = new Mux({
    role: 'gateway',
    send: (b) => sent.push(decodeFrame(b).type),
    onFatal: (r) => fatal.push(r),
    maxStreams: 4,
    now: () => now,
  });
  now += 19_000;
  mux.tick();
  assertEquals(sent, []);
  now += 2_000;
  mux.tick();
  assertEquals(sent, [FrameType.PING]);
  mux.receive(encodeFrame(FrameType.PONG, 0));
  now += 59_000;
  mux.tick();
  assertEquals(fatal, []);
  now += 2_000;
  mux.tick();
  assertEquals(fatal, ['tunnel_dead']);
  // A ping is answered with a pong.
  const other = pair();
  other.gateway.receive(encodeFrame(FrameType.PING, 0));
  assertEquals(other.wire.at(-1)?.type, FrameType.PONG);
});

Deno.test('tunnel: protocol error type', () => {
  assertThrows(() => decodeFrame(new Uint8Array(0)), /short/);
  assert(new TunnelProtocolError('x') instanceof Error);
});
