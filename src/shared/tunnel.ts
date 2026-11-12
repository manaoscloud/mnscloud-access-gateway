// Connector tunnel: binary frames and stream multiplexing over one WebSocket.
//
//   frame   = [type u8][stream u32 big endian][payload]       (whole frame <= 64 KiB)
//   OPEN      gateway -> connector, stream = new id, payload JSON {connectionUuid, host, port}
//   OPEN_OK   connector -> gateway
//   OPEN_FAIL connector -> gateway, payload JSON {code}
//   DATA      both ways, per stream, limited by the peer's CREDIT window (start 256 KiB)
//   CLOSE     both ways, ends one stream
//   CREDIT    both ways, payload u32: bytes the sender of CREDIT is ready to receive again
//   PING/PONG both ways, stream 0
//
// Only the gateway may send OPEN. A connector that sends OPEN, or either side sending an unknown
// type, an oversized frame or data beyond the granted window, ends the whole tunnel.

export const FrameType = {
  OPEN: 1,
  OPEN_OK: 2,
  OPEN_FAIL: 3,
  DATA: 4,
  CLOSE: 5,
  CREDIT: 6,
  PING: 7,
  PONG: 8,
} as const;

export const HEADER_BYTES = 5;
export const MAX_FRAME_BYTES = 64 * 1024;
export const MAX_PAYLOAD_BYTES = MAX_FRAME_BYTES - HEADER_BYTES;
export const DATA_CHUNK_BYTES = 32 * 1024;
export const INITIAL_WINDOW = 256 * 1024;
export const PING_INTERVAL_MS = 20000;
export const DEAD_AFTER_MS = 60000;
export const MAX_OPEN_PAYLOAD = 1024;

export class TunnelProtocolError extends Error {}

export interface Frame {
  type: number;
  stream: number;
  payload: Uint8Array;
}

const KNOWN = new Set<number>(Object.values(FrameType));

export function encodeFrame(
  type: number,
  stream: number,
  payload: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (!KNOWN.has(type)) throw new TunnelProtocolError('unknown frame type');
  if (HEADER_BYTES + payload.length > MAX_FRAME_BYTES) {
    throw new TunnelProtocolError('frame too large');
  }
  const out = new Uint8Array(HEADER_BYTES + payload.length);
  out[0] = type;
  new DataView(out.buffer).setUint32(1, stream >>> 0);
  out.set(payload, HEADER_BYTES);
  return out;
}

export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.length < HEADER_BYTES) throw new TunnelProtocolError('short frame');
  if (bytes.length > MAX_FRAME_BYTES) throw new TunnelProtocolError('frame too large');
  const type = bytes[0];
  if (!KNOWN.has(type)) throw new TunnelProtocolError('unknown frame type');
  const stream = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(1);
  return { type, stream, payload: bytes.subarray(HEADER_BYTES) };
}

export function creditPayload(bytes: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, bytes >>> 0);
  return out;
}

export interface OpenSpec {
  connectionUuid: string;
  host: string;
  port: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encodeOpen(spec: OpenSpec): Uint8Array {
  return encoder.encode(JSON.stringify({
    connectionUuid: spec.connectionUuid,
    host: spec.host,
    port: spec.port,
  }));
}

export function decodeOpen(payload: Uint8Array): OpenSpec | null {
  if (payload.length > MAX_OPEN_PAYLOAD) return null;
  try {
    const value = JSON.parse(decoder.decode(payload));
    if (
      typeof value?.connectionUuid !== 'string' || typeof value?.host !== 'string' ||
      !Number.isInteger(value?.port)
    ) return null;
    return { connectionUuid: value.connectionUuid, host: value.host, port: value.port };
  } catch {
    return null;
  }
}

export function decodeFailCode(payload: Uint8Array): string {
  try {
    const code = JSON.parse(decoder.decode(payload.subarray(0, 256)))?.code;
    return typeof code === 'string' && /^[a-z0-9_]{1,48}$/.test(code) ? code : 'open_failed';
  } catch {
    return 'open_failed';
  }
}

/** Failure of `Mux.open` (the connector refused, timed out, or the tunnel is gone). */
export class OpenError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export class TunnelStream {
  #queue: Uint8Array[] = [];
  #readWaiter: ((chunk: Uint8Array | null) => void) | null = null;
  #sendCredit = INITIAL_WINDOW;
  #creditWaiters: (() => void)[] = [];
  #recvWindow = INITIAL_WINDOW;
  #pendingGrant = 0;
  #remoteClosed = false;
  #closed = false;

  constructor(readonly id: number, private readonly host: StreamHost) {}

  get closed() {
    return this.#closed || this.#remoteClosed;
  }

  /** Next chunk from the peer (null at the end). Reading returns window to the peer. */
  async read(): Promise<Uint8Array | null> {
    let chunk = this.#queue.shift();
    if (chunk === undefined) {
      if (this.#remoteClosed || this.#closed) return null;
      const next = await new Promise<Uint8Array | null>((resolve) => (this.#readWaiter = resolve));
      if (next === null) return null;
      chunk = next;
    }
    this.#pendingGrant += chunk.length;
    if (this.#pendingGrant >= DATA_CHUNK_BYTES || this.#queue.length === 0) this.#grant();
    return chunk;
  }

  #grant() {
    if (this.#pendingGrant === 0 || this.#closed || this.#remoteClosed) {
      this.#pendingGrant = 0;
      return;
    }
    const n = this.#pendingGrant;
    this.#pendingGrant = 0;
    this.#recvWindow += n;
    this.host.sendFrame(FrameType.CREDIT, this.id, creditPayload(n));
  }

  /** Sends bytes, waiting for the peer's window; rejects when the stream ended. */
  async write(bytes: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < bytes.length) {
      while (this.#sendCredit <= 0) {
        if (this.closed) throw new Error('stream closed');
        await new Promise<void>((resolve) => this.#creditWaiters.push(resolve));
      }
      if (this.closed) throw new Error('stream closed');
      const n = Math.min(DATA_CHUNK_BYTES, this.#sendCredit, bytes.length - offset);
      this.#sendCredit -= n;
      this.host.sendFrame(FrameType.DATA, this.id, bytes.subarray(offset, offset + n));
      offset += n;
    }
  }

  /** Ends the stream (idempotent). */
  close() {
    if (this.#closed) return;
    this.#closed = true;
    if (!this.#remoteClosed) this.host.sendFrame(FrameType.CLOSE, this.id);
    this.host.release(this.id);
    this.#wake();
  }

  /** Called by the multiplexer. */
  deliver(chunk: Uint8Array) {
    if (this.#closed || this.#remoteClosed) return;
    if (chunk.length > this.#recvWindow) throw new TunnelProtocolError('data beyond window');
    this.#recvWindow -= chunk.length;
    if (this.#readWaiter) {
      const waiter = this.#readWaiter;
      this.#readWaiter = null;
      waiter(chunk);
    } else this.#queue.push(chunk);
  }

  addCredit(n: number) {
    if (this.#sendCredit + n > INITIAL_WINDOW) throw new TunnelProtocolError('credit overflow');
    this.#sendCredit += n;
    for (const resolve of this.#creditWaiters.splice(0)) resolve();
  }

  remoteClose() {
    this.#remoteClosed = true;
    this.host.release(this.id);
    this.#wake();
  }

  #wake() {
    const waiter = this.#readWaiter;
    this.#readWaiter = null;
    if (waiter && this.#queue.length === 0) waiter(null);
    for (const resolve of this.#creditWaiters.splice(0)) resolve();
  }
}

export interface StreamHost {
  sendFrame(type: number, stream: number, payload?: Uint8Array): void;
  release(id: number): void;
}

export interface MuxOptions {
  role: 'gateway' | 'connector';
  /** Sends one binary frame on the WebSocket. */
  send(bytes: Uint8Array): void;
  /** The tunnel must end (protocol violation, dead peer). */
  onFatal(reason: string): void;
  /** Maximum concurrent streams. */
  maxStreams: number;
  /** Connector side: the gateway opened a stream; answer with `acceptOpen` or `rejectOpen`. */
  onOpen?(id: number, spec: OpenSpec): void;
  now?(): number;
}

interface PendingOpen {
  stream: TunnelStream;
  resolve(stream: TunnelStream): void;
  reject(error: OpenError): void;
  timer: ReturnType<typeof setTimeout>;
}

export class Mux implements StreamHost {
  readonly streams = new Map<number, TunnelStream>();
  #pending = new Map<number, PendingOpen>();
  #nextId = 1;
  #lastReceived: number;
  #lastSent: number;
  #timer: ReturnType<typeof setInterval> | null = null;
  #dead = false;

  constructor(private readonly options: MuxOptions) {
    this.#lastReceived = this.#now();
    this.#lastSent = this.#now();
  }

  #now() {
    return this.options.now ? this.options.now() : Date.now();
  }

  get streamCount() {
    return this.streams.size + this.#pending.size;
  }

  /** Starts the idle ping and the dead-peer check (call once the handshake is done). */
  startKeepalive(intervalMs = 5000) {
    this.#timer = setInterval(() => this.tick(), intervalMs);
  }

  tick() {
    const now = this.#now();
    if (now - this.#lastReceived > DEAD_AFTER_MS) {
      this.#fatal('tunnel_dead');
      return;
    }
    if (now - this.#lastSent >= PING_INTERVAL_MS) this.sendFrame(FrameType.PING, 0);
  }

  sendFrame(type: number, stream: number, payload?: Uint8Array) {
    if (this.#dead) return;
    this.#lastSent = this.#now();
    try {
      this.options.send(encodeFrame(type, stream, payload));
    } catch {
      this.#fatal('send_failed');
    }
  }

  release(id: number) {
    this.streams.delete(id);
  }

  #fatal(reason: string) {
    if (this.#dead) return;
    this.close(reason);
    this.options.onFatal(reason);
  }

  /** Ends every stream and the timers (the WebSocket is closed by the caller). */
  close(reason = 'tunnel_closed') {
    this.#dead = true;
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    for (const [id, pending] of this.#pending) {
      clearTimeout(pending.timer);
      pending.reject(new OpenError(reason));
      this.#pending.delete(id);
    }
    for (const stream of [...this.streams.values()]) stream.remoteClose();
    this.streams.clear();
  }

  /** Gateway side: opens one stream toward the connector and waits for OPEN_OK. */
  open(spec: OpenSpec, timeoutMs = 20000): Promise<TunnelStream> {
    if (this.options.role !== 'gateway') throw new TunnelProtocolError('only the gateway opens');
    if (this.#dead) return Promise.reject(new OpenError('tunnel_closed'));
    if (this.streamCount >= this.options.maxStreams) {
      return Promise.reject(new OpenError('too_many_streams'));
    }
    if (this.#nextId >= 0xffffffff) return Promise.reject(new OpenError('tunnel_exhausted'));
    const id = this.#nextId++;
    const stream = new TunnelStream(id, this);
    return new Promise<TunnelStream>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        this.sendFrame(FrameType.CLOSE, id);
        reject(new OpenError('open_timeout'));
      }, timeoutMs);
      this.#pending.set(id, { stream, resolve, reject, timer });
      this.streams.set(id, stream);
      this.sendFrame(FrameType.OPEN, id, encodeOpen(spec));
    });
  }

  /** Connector side: accept a stream the gateway opened. */
  acceptOpen(id: number): TunnelStream {
    const stream = new TunnelStream(id, this);
    this.streams.set(id, stream);
    this.sendFrame(FrameType.OPEN_OK, id);
    return stream;
  }

  rejectOpen(id: number, code: string) {
    this.sendFrame(FrameType.OPEN_FAIL, id, encoder.encode(JSON.stringify({ code })));
  }

  /** One binary message received from the WebSocket. Violations end the tunnel. */
  receive(bytes: Uint8Array) {
    if (this.#dead) return;
    this.#lastReceived = this.#now();
    try {
      this.#dispatch(decodeFrame(bytes));
    } catch (error) {
      this.#fatal(error instanceof TunnelProtocolError ? error.message : 'protocol_error');
    }
  }

  #dispatch(frame: Frame) {
    const { type, stream: id, payload } = frame;
    const gateway = this.options.role === 'gateway';
    switch (type) {
      case FrameType.PING:
        this.sendFrame(FrameType.PONG, 0);
        return;
      case FrameType.PONG:
        return;
      case FrameType.OPEN: {
        // Only the gateway opens streams: a connector sending OPEN ends the tunnel.
        if (gateway) throw new TunnelProtocolError('open from connector');
        if (id === 0 || this.streams.has(id)) throw new TunnelProtocolError('bad stream id');
        const spec = decodeOpen(payload);
        if (!spec) {
          this.rejectOpen(id, 'invalid_open');
          return;
        }
        if (this.streams.size >= this.options.maxStreams) {
          this.rejectOpen(id, 'too_many_streams');
          return;
        }
        this.options.onOpen?.(id, spec);
        return;
      }
      case FrameType.OPEN_OK:
      case FrameType.OPEN_FAIL: {
        if (!gateway) throw new TunnelProtocolError('unexpected open reply');
        const pending = this.#pending.get(id);
        if (!pending) return;
        this.#pending.delete(id);
        clearTimeout(pending.timer);
        if (type === FrameType.OPEN_OK) pending.resolve(pending.stream);
        else {
          this.streams.delete(id);
          pending.reject(new OpenError(decodeFailCode(payload)));
        }
        return;
      }
      case FrameType.DATA: {
        const stream = this.streams.get(id);
        if (stream && !this.#pending.has(id)) stream.deliver(payload.slice());
        else if (stream) throw new TunnelProtocolError('data before open reply');
        return;
      }
      case FrameType.CREDIT: {
        if (payload.length !== 4) throw new TunnelProtocolError('bad credit');
        const n = new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0);
        this.streams.get(id)?.addCredit(n);
        return;
      }
      case FrameType.CLOSE:
        this.streams.get(id)?.remoteClose();
        return;
    }
  }
}
