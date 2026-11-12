// Minimal RouterOS API client over TLS (API-SSL, port 8729) for "Testar acesso" and device facts.
// Only three sentences are ever sent: /login, /system/identity/print, /system/resource/print.
// The plain API (8728) is refused: it would carry the password in clear text.
// The certificate is self-signed on most devices, so trust is a SHA-256 pin of the leaf
// certificate (pinned on first use by the API), checked before any credential is sent.

import net from 'node:net';
import tls from 'node:tls';

export class RouterOsApiError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

export function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  if (length < 0x4000) return Uint8Array.of((length >> 8) | 0x80, length & 0xff);
  if (length < 0x200000) {
    return Uint8Array.of((length >> 16) | 0xc0, (length >> 8) & 0xff, length & 0xff);
  }
  if (length < 0x10000000) {
    return Uint8Array.of(
      (length >>> 24) | 0xe0,
      (length >> 16) & 0xff,
      (length >> 8) & 0xff,
      length & 0xff,
    );
  }
  return Uint8Array.of(
    0xf0,
    (length >>> 24) & 0xff,
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  );
}

const encoder = new TextEncoder();

export function encodeSentence(words: string[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const word of words) {
    const bytes = encoder.encode(word);
    parts.push(encodeLength(bytes.length), bytes);
  }
  parts.push(Uint8Array.of(0));
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const MAX_WORD = 1024 * 1024;
const MAX_SENTENCES = 1000;

/** Incremental decoder of API sentences (arrays of words). */
export class SentenceReader {
  #buffer = new Uint8Array(0);
  #words: string[] = [];
  #decoder = new TextDecoder();

  push(chunk: Uint8Array): string[][] {
    const merged = new Uint8Array(this.#buffer.length + chunk.length);
    merged.set(this.#buffer);
    merged.set(chunk, this.#buffer.length);
    this.#buffer = merged;
    const sentences: string[][] = [];
    for (;;) {
      const header = decodeLength(this.#buffer);
      if (!header) break;
      const [length, size] = header;
      if (length > MAX_WORD) throw new RouterOsApiError('protocol', 'Oversized API word');
      if (this.#buffer.length < size + length) break;
      const word = this.#decoder.decode(this.#buffer.subarray(size, size + length));
      this.#buffer = this.#buffer.slice(size + length);
      if (length === 0) {
        sentences.push(this.#words);
        this.#words = [];
      } else {
        this.#words.push(word);
        if (this.#words.length > 10000) {
          throw new RouterOsApiError('protocol', 'Oversized API sentence');
        }
      }
    }
    return sentences;
  }
}

export function decodeLength(bytes: Uint8Array): [number, number] | null {
  if (!bytes.length) return null;
  const b = bytes[0];
  if ((b & 0x80) === 0) return [b, 1];
  if ((b & 0xc0) === 0x80) return bytes.length < 2 ? null : [((b & 0x3f) << 8) | bytes[1], 2];
  if ((b & 0xe0) === 0xc0) {
    return bytes.length < 3 ? null : [((b & 0x1f) << 16) | (bytes[1] << 8) | bytes[2], 3];
  }
  if ((b & 0xf0) === 0xe0) {
    return bytes.length < 4
      ? null
      : [(((b & 0x0f) << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0, 4];
  }
  if (b === 0xf0) {
    return bytes.length < 5
      ? null
      : [((bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4]) >>> 0, 5];
  }
  throw new RouterOsApiError('protocol', 'Invalid API length');
}

export type Reply = { type: string; attributes: Record<string, string> };

function parseReply(words: string[]): Reply {
  const attributes: Record<string, string> = {};
  for (const word of words.slice(1)) {
    if (!word.startsWith('=')) continue;
    const sep = word.indexOf('=', 1);
    if (sep > 0) attributes[word.slice(1, sep)] = word.slice(sep + 1);
  }
  return { type: words[0] ?? '', attributes };
}

export interface ApiTransport {
  write(bytes: Uint8Array): void;
  onData(handler: (chunk: Uint8Array) => void): void;
  onClose(handler: (error?: Error) => void): void;
  close(): void;
}

/** Sends one command at a time and collects its "!re" replies until "!done". */
export class RouterOsApi {
  #reader = new SentenceReader();
  #waiting: { resolve: (r: Reply[]) => void; reject: (e: Error) => void; replies: Reply[] } | null =
    null;
  #closed: Error | null = null;

  constructor(private readonly transport: ApiTransport, private readonly timeoutMs = 15000) {
    transport.onData((chunk) => {
      let sentences: string[][];
      try {
        sentences = this.#reader.push(chunk);
      } catch (error) {
        this.#fail(error as Error);
        return;
      }
      for (const sentence of sentences) this.#sentence(parseReply(sentence));
    });
    transport.onClose((error) =>
      this.#fail(error ?? new RouterOsApiError('closed', 'API connection closed'))
    );
  }

  #sentence(reply: Reply) {
    const waiting = this.#waiting;
    if (!waiting) return;
    if (reply.type === '!re') {
      if (waiting.replies.length < MAX_SENTENCES) waiting.replies.push(reply);
      return;
    }
    this.#waiting = null;
    if (reply.type === '!done') waiting.resolve(waiting.replies);
    else if (reply.type === '!trap') {
      waiting.reject(new RouterOsApiError('trap', reply.attributes.message ?? 'Command failed'));
    } else {
      waiting.reject(
        new RouterOsApiError('fatal', reply.attributes.message ?? 'API session ended'),
      );
    }
  }

  #fail(error: Error) {
    this.#closed ??= error;
    const waiting = this.#waiting;
    this.#waiting = null;
    waiting?.reject(error);
  }

  command(words: string[]): Promise<Reply[]> {
    if (this.#closed) return Promise.reject(this.#closed);
    if (this.#waiting) return Promise.reject(new RouterOsApiError('busy', 'Command in progress'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#waiting = null;
        reject(new RouterOsApiError('timeout', 'The device did not answer in time'));
      }, this.timeoutMs);
      this.#waiting = {
        resolve: (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
        replies: [],
      };
      this.transport.write(encodeSentence(words));
    });
  }

  async login(username: string, password: string) {
    try {
      const replies = await this.command(['/login', `=name=${username}`, `=password=${password}`]);
      // RouterOS before 6.43 answers with a challenge (=ret=); MD5 challenge login is refused.
      if (replies.length === 0) return;
    } catch (error) {
      if (error instanceof RouterOsApiError && error.code === 'trap') {
        throw new RouterOsApiError('auth_failed', 'The device refused the credential');
      }
      throw error;
    }
  }

  async facts() {
    const identity = (await this.command(['/system/identity/print']))[0]?.attributes ?? {};
    const resource = (await this.command(['/system/resource/print']))[0]?.attributes ?? {};
    return {
      identity: identity.name,
      version: resource.version,
      boardName: resource['board-name'],
      architecture: resource['architecture-name'],
      uptime: resource.uptime,
      cpuLoad: resource['cpu-load'],
      freeMemory: resource['free-memory'],
      totalMemory: resource['total-memory'],
    };
  }

  close() {
    this.transport.close();
  }
}

/** "AA:BB:..." (node) -> "SHA256:<base64>" (same form as the SSH host key pin of the API). */
export function tlsPin(fingerprint256: string): string {
  const hex = fingerprint256.replace(/:/g, '');
  const bytes = Uint8Array.from(hex.match(/.{2}/g) ?? [], (h) => parseInt(h, 16));
  return `SHA256:${btoa(String.fromCharCode(...bytes)).replace(/=+$/, '')}`;
}

export interface TlsConnection {
  transport: ApiTransport;
  pin: string;
}

/**
 * Opens TLS to the device without CA validation and returns the leaf certificate pin. The caller
 * compares the pin (or asks the API to pin it) before sending the login sentence.
 */
export function connectApiSsl(
  address: string,
  port: number,
  timeoutMs: number,
  /** Connector transport: unix socket of the controller bridge (no network). */
  bridge?: string,
): Promise<TlsConnection> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      ...(bridge ? { socket: net.createConnection({ path: bridge }) } : { host: address, port }),
      rejectUnauthorized: false,
      // RouterOS certificates rarely name the address; the pin replaces hostname checks.
      checkServerIdentity: () => undefined,
      minVersion: 'TLSv1.2',
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new RouterOsApiError('connect_failed', 'TLS connection timed out'));
    }, timeoutMs);
    socket.once('error', (error: Error) => {
      clearTimeout(timer);
      reject(new RouterOsApiError('tls_failed', error.message));
    });
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const certificate = socket.getPeerCertificate();
      if (!certificate?.fingerprint256) {
        socket.destroy();
        reject(new RouterOsApiError('tls_failed', 'The device presented no certificate'));
        return;
      }
      resolve({
        pin: tlsPin(certificate.fingerprint256),
        transport: {
          write: (bytes) => socket.write(bytes),
          onData: (handler) =>
            socket.on('data', (chunk: Uint8Array) => handler(new Uint8Array(chunk))),
          onClose: (handler) => {
            socket.on('close', () => handler());
            socket.on('error', (error: Error) => handler(error));
          },
          close: () => socket.destroy(),
        },
      });
    });
  });
}
