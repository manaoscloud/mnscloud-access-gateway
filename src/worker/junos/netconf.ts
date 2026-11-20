import { Element, escapeXml, is, MAX_FRAME, only, parseXml, ProtocolError } from './xml.ts';
export const NC = 'urn:ietf:params:xml:ns:netconf:base:1.0';
export const BASE = 'urn:ietf:params:netconf:base:1.0';
export const CAP = 'urn:ietf:params:netconf:capability:';
export const JUNOS = 'http://xml.juniper.net/netconf/junos/1.0'; // NOSONAR namespace identifier, not a URL that is fetched
export interface Channel {
  on(event: 'data', cb: (data: Uint8Array) => void): unknown;
  on(event: 'error', cb: (error: unknown) => void): unknown;
  on(event: 'close' | 'end', cb: () => void): unknown;
  write(data: string): unknown;
  close(): unknown;
}
/** Already authenticated and host-key-pinned ssh2.Client only. Never connects or authenticates. */
export interface PinnedClient {
  subsys(
    name: string,
    cb: (error: Error | undefined, channel: Channel) => void,
  ): unknown;
}
const END = new TextEncoder().encode(']]>]]>');
export class RpcError extends ProtocolError {
  constructor(readonly tag: string) {
    super('RPC_ERROR');
  }
}
const TAGS = new Set([
  'in-use',
  'invalid-value',
  'too-big',
  'missing-attribute',
  'bad-attribute',
  'unknown-attribute',
  'missing-element',
  'bad-element',
  'unknown-element',
  'unknown-namespace',
  'access-denied',
  'lock-denied',
  'resource-denied',
  'rollback-failed',
  'data-exists',
  'data-missing',
  'operation-not-supported',
  'operation-failed',
  'partial-operation',
  'malformed-message',
]);
function frameEnd(b: Uint8Array): number {
  outer: for (let i = 0; i <= b.length - END.length; i++) {
    for (let j = 0; j < END.length; j++) {
      if (b[i + j] !== END[j]) continue outer;
    }
    return i;
  }
  return -1;
}
export class Netconf {
  readonly capabilities = new Set<string>();
  sessionId = '';
  private buffer = new Uint8Array();
  private closed = false;
  private nextId = 0;
  private pending: {
    resolve: (el: Element) => void;
    reject: (e: unknown) => void;
  } | null = null;
  private constructor(private readonly channel: Channel) {
    channel.on('data', (b) => this.data(b));
    channel.on('error', () => this.close('TRANSPORT'));
    channel.on('end', () => this.close());
    channel.on('close', () => this.close());
  }
  static async open(
    client: PinnedClient,
    signal: AbortSignal,
    timeoutMs = 10000,
  ): Promise<Netconf> {
    if (signal.aborted) throw new ProtocolError('CANCELLED');
    const channel = await new Promise<Channel>((resolve, reject) => {
      let done = false;
      const finish = (error?: ProtocolError, c?: Channel) => {
        if (done) {
          c?.close();
          return;
        }
        done = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        if (error) reject(error);
        else resolve(c!);
      };
      const abort = () => finish(new ProtocolError('CANCELLED'));
      const timer = setTimeout(
        () => finish(new ProtocolError('TIMEOUT')),
        timeoutMs,
      );
      signal.addEventListener('abort', abort, { once: true });
      try {
        client.subsys(
          'netconf',
          (error, c) =>
            finish(
              error ? new ProtocolError('SUBSYSTEM_UNAVAILABLE') : undefined,
              c,
            ),
        );
      } catch {
        finish(new ProtocolError('SUBSYSTEM_UNAVAILABLE'));
      }
    });
    const nc = new Netconf(channel);
    try {
      const waiting = nc.wait(signal, timeoutMs);
      try {
        channel.write(
          // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
          `<hello xmlns="${NC}"><capabilities><capability>${BASE}</capability></capabilities></hello>]]>]]>`,
        );
      } catch {
        nc.close('TRANSPORT');
      }
      const hello = await waiting;
      if (
        !is(hello, 'hello', NC) || hello.text.trim() ||
        hello.children.length !== 2
      ) throw new ProtocolError();
      const sid = only(hello, 'session-id', NC);
      if (
        sid.children.length || !/^\d{1,10}$/.test(sid.text.trim()) ||
        Number(sid.text) < 1 || Number(sid.text) > 4294967295
      ) throw new ProtocolError();
      nc.sessionId = sid.text.trim();
      const capabilities = only(hello, 'capabilities', NC);
      if (capabilities.text.trim() || capabilities.children.length > 128) {
        throw new ProtocolError();
      }
      for (const el of capabilities.children) {
        if (
          !is(el, 'capability', NC) || el.children.length || !el.text.trim() ||
          el.text.length > 1024
        ) throw new ProtocolError();
        nc.capabilities.add(el.text.trim());
      }
      if (!nc.capabilities.has(BASE)) {
        throw new ProtocolError('UNSUPPORTED_BASE');
      }
      return nc;
    } catch (e) {
      nc.close();
      throw e;
    }
  }
  get usable() {
    return !this.closed;
  }
  close(code = 'CLOSED') {
    if (this.closed) return;
    this.closed = true;
    const p = this.pending;
    this.pending = null;
    p?.reject(new ProtocolError(code));
    try {
      this.channel.close();
    } catch { /* no raw transport errors */ }
  }
  private data(chunk: Uint8Array) {
    if (this.closed) return;
    if (
      !(chunk instanceof Uint8Array) ||
      this.buffer.length + chunk.length > MAX_FRAME + END.length
    ) {
      this.close('FRAME_LIMIT');
      return;
    }
    const merged = new Uint8Array(this.buffer.length + chunk.length);
    merged.set(this.buffer);
    merged.set(chunk, this.buffer.length);
    this.buffer = merged;
    const index = frameEnd(merged);
    if (index < 0) return;
    if (index + END.length !== merged.length || !this.pending) {
      this.close('UNEXPECTED_FRAME');
      return;
    }
    const pending = this.pending;
    this.pending = null;
    this.buffer = new Uint8Array();
    try {
      pending.resolve(parseXml(merged.subarray(0, index)));
    } catch (e) {
      pending.reject(e);
      this.close('XML');
    }
  }
  private wait(signal: AbortSignal, timeoutMs: number): Promise<Element> {
    if (this.closed || this.pending || signal.aborted || timeoutMs <= 0) {
      return Promise.reject(
        new ProtocolError(signal.aborted ? 'CANCELLED' : 'CLOSED'),
      );
    }
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
      };
      const abort = () => this.close('CANCELLED');
      const timer = setTimeout(() => this.close('TIMEOUT'), timeoutMs);
      this.pending = {
        resolve: (el) => {
          cleanup();
          resolve(el);
        },
        reject: (e) => {
          cleanup();
          reject(e);
        },
      };
      signal.addEventListener('abort', abort, { once: true });
    });
  }
  async rpc(
    body: string,
    signal: AbortSignal,
    timeoutMs = 10000,
  ): Promise<Element> {
    if (!this.usable || signal.aborted || timeoutMs <= 0) {
      throw new ProtocolError(
        signal.aborted ? 'CANCELLED' : timeoutMs <= 0 ? 'TIMEOUT' : 'CLOSED',
      );
    }
    if (this.pending) throw new ProtocolError('CONCURRENT_RPC');
    if (new TextEncoder().encode(body).length > MAX_FRAME - 256) {
      throw new ProtocolError('FRAME_LIMIT');
    }
    const id = String(++this.nextId);
    const waiting = this.wait(signal, timeoutMs);
    try {
      this.channel.write(
        // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
        `<rpc xmlns="${NC}" message-id="${id}">${body}</rpc>]]>]]>`,
      );
    } catch {
      this.close('TRANSPORT');
    }
    const el = await waiting;
    try {
      if (
        !is(el, 'rpc-reply', NC) || el.attrs.get('{}message-id') !== id ||
        el.text.trim()
      ) throw new ProtocolError('REPLY_MISMATCH');
      const errors = el.children.filter((x) => is(x, 'rpc-error', NC));
      if (errors.length) {
        const t = only(errors[0], 'error-tag', NC);
        const tag = t.text.trim();
        throw new RpcError(TAGS.has(tag) ? tag : 'unknown');
      }
      if (el.children.some((x) => x.name === 'rpc-error')) {
        throw new ProtocolError('ERROR_NAMESPACE');
      }
      return el;
    } catch (e) {
      if (!(e instanceof RpcError)) this.close();
      throw e;
    }
  }
  async ok(body: string, signal: AbortSignal, timeoutMs = 10000) {
    const el = await this.rpc(body, signal, timeoutMs);
    if (
      el.children.length !== 1 || !is(el.children[0], 'ok', NC) ||
      el.children[0].children.length || el.children[0].text.trim()
    ) {
      this.close();
      throw new ProtocolError('EXPECTED_OK');
    }
  }
  async loadSet(
    commands: readonly string[],
    signal: AbortSignal,
    timeoutMs: number,
  ) {
    const el = await this.rpc(
      // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<load-configuration action="set" format="text"><configuration-set>${
        escapeXml(commands.join('\n'))
      }</configuration-set></load-configuration>`,
      signal,
      timeoutMs,
    );
    // Junos NETCONF uses load-configuration-results/ok, unlike Junos XML protocol load-success.
    if (el.children.length !== 1) throw new ProtocolError('LOAD_RESULT');
    const result = only(el, 'load-configuration-results', NC);
    if (
      result.children.length !== 1 || result.text.trim() ||
      !is(result.children[0], 'ok', NC) || result.children[0].children.length ||
      result.children[0].text.trim()
    ) throw new ProtocolError('LOAD_RESULT');
  }
}
