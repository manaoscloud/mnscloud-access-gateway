// Native WinRM over HTTPS (WS-Man / WinRS command shell) for the Windows dialect. No local program
// is ever run and no PowerShell remoting (PSRP) is spoken: the only resource is the cmd shell
// (`http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd`) with the lifecycle
// Create -> Command -> Receive* -> Signal(terminate) -> Delete.
//
// Transport rules (fail closed, all enforced here):
//   - TLS only, on the raw socket of `connectApiSsl` (so the connector bridge works the same way);
//     the caller checks the SHA256 pin BEFORE any credential is built, never plain HTTP;
//   - one keep-alive connection, fixed `POST /wsman` on the assigned address: a redirect (3xx) is
//     an error, never followed; there is no way to reach another destination;
//   - HTTP Basic is the only authentication (CredSSP, Kerberos, NTLM and multihop are not spoken);
//   - strict bounded parsing of headers, bodies and XML (no DTD, no entities, no CDATA);
//   - every response must carry the RelatesTo of the request and the shell and command ids that
//     were issued; stdout/stderr arrive as base64 and are decoded with a hard byte cap.

import { Buffer } from 'node:buffer';
import type { ApiTransport } from './routeros_api.ts';

export type WinrmErrorCode =
  | 'auth_failed'
  | 'redirect'
  | 'http_status'
  | 'protocol'
  | 'xml'
  | 'fault'
  | 'timeout'
  | 'closed'
  | 'output_limit'
  | 'cancelled';

export class WinrmError extends Error {
  constructor(readonly code: WinrmErrorCode, message: string, readonly detail = '') {
    super(message);
  }
}

// ---------------------------------------------------------------------------------------------
// Bounded XML

export interface XmlNode {
  /** Expanded name and exact qualified name; prefixes may vary but namespace URIs may not. */
  name: string;
  ns: string;
  qname: string;
  namespaces: Record<string, string>;
  attrs: Record<string, string>;
  children: XmlNode[];
  text: string;
}

export const XML_LIMITS = { bytes: 2 * 1024 * 1024, depth: 24, nodes: 4000, attrs: 16 };
const NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}(?::[A-Za-z_][A-Za-z0-9_.-]{0,63})?$/;
const ENTITY = /&(?:amp|lt|gt|quot|apos|#[0-9]{1,6}|#x[0-9a-fA-F]{1,5});/g;

function decodeEntities(text: string): string {
  if (!text.includes('&')) return text;
  const out = text.replace(ENTITY, (whole) => {
    switch (whole) {
      case '&amp;':
        return '&';
      case '&lt;':
        return '<';
      case '&gt;':
        return '>';
      case '&quot;':
        return '"';
      case '&apos;':
        return "'";
    }
    const code = whole[2] === 'x'
      ? parseInt(whole.slice(3, -1), 16)
      : parseInt(whole.slice(2, -1), 10);
    if (code === 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
      throw new WinrmError('xml', 'Invalid character reference');
    }
    return String.fromCodePoint(code);
  });
  return out;
}

/** Text between tags must not hold a raw `&` that is not a permitted reference. */
function assertNoBareAmpersand(raw: string) {
  if (raw.includes('&') && raw.replace(ENTITY, '').includes('&')) {
    throw new WinrmError('xml', 'Entity not allowed');
  }
}

/**
 * Parses a SOAP document into a small tree. No DOCTYPE, no ENTITY, no CDATA, no comments, no
 * processing instruction other than the XML declaration, bounded depth, nodes, attributes and size:
 * a hostile or broken server can neither expand entities nor make the worker fetch anything.
 */
export function parseXml(input: string): XmlNode {
  if (input.length > XML_LIMITS.bytes) throw new WinrmError('xml', 'XML too large');
  let i = 0;
  const decl = /^\s*<\?xml\s[^<>?]{0,200}\?>/.exec(input);
  if (decl) i = decl[0].length;
  const stack: XmlNode[] = [];
  let root: XmlNode | null = null;
  let nodes = 0;
  const local = (name: string) => name.slice(name.indexOf(':') + 1);
  while (i < input.length) {
    const lt = input.indexOf('<', i);
    const text = input.slice(i, lt < 0 ? input.length : lt);
    if (text) {
      if (!stack.length) {
        if (text.trim()) throw new WinrmError('xml', 'Text outside the root element');
      } else {
        assertNoBareAmpersand(text);
        stack[stack.length - 1].text += decodeEntities(text);
      }
    }
    if (lt < 0) break;
    if (input.startsWith('<!', lt) || input.startsWith('<?', lt)) {
      throw new WinrmError('xml', 'DTD, comment, CDATA and instructions are not allowed');
    }
    const gt = input.indexOf('>', lt);
    if (gt < 0) throw new WinrmError('xml', 'Unterminated tag');
    const tag = input.slice(lt + 1, gt);
    i = gt + 1;
    if (tag.startsWith('/')) {
      const name = tag.slice(1).trim();
      const open = stack.pop();
      if (!open || !NAME.test(name) || name !== open.qname) {
        throw new WinrmError('xml', 'Mismatched closing tag');
      }
      continue;
    }
    const selfClosing = tag.endsWith('/');
    const body = selfClosing ? tag.slice(0, -1) : tag;
    const head = /^([^\s/>]+)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"<]*"|'[^'<]*'))*)\s*$/.exec(body);
    if (!head || !NAME.test(head[1])) throw new WinrmError('xml', 'Invalid tag');
    if (++nodes > XML_LIMITS.nodes) throw new WinrmError('xml', 'Too many elements');
    const attrs: Record<string, string> = {};
    const parent = stack[stack.length - 1];
    const namespaces: Record<string, string> = {
      xml: 'http://www.w3.org/XML/1998/namespace', // NOSONAR namespace identifier, not a URL that is fetched
      ...parent?.namespaces,
    };
    const rawAttrs = new Map<string, string>();
    let count = 0;
    for (const m of head[2].matchAll(/\s+([^\s=/>]+)\s*=\s*(?:"([^"<]*)"|'([^'<]*)')/g)) {
      if (++count > XML_LIMITS.attrs || !NAME.test(m[1])) {
        throw new WinrmError('xml', 'Invalid attribute');
      }
      const raw = m[2] ?? m[3] ?? '';
      assertNoBareAmpersand(raw);
      if (rawAttrs.has(m[1])) throw new WinrmError('xml', 'Duplicate attribute');
      rawAttrs.set(m[1], decodeEntities(raw));
    }
    for (const [name, value] of rawAttrs) {
      if (name === 'xmlns') namespaces[''] = value;
      else if (name.startsWith('xmlns:')) {
        const prefix = name.slice(6);
        if (!value || prefix === 'xmlns' || (prefix === 'xml' && value !== namespaces.xml)) {
          throw new WinrmError('xml', 'Invalid namespace declaration');
        }
        namespaces[prefix] = value;
      }
    }
    const namespace = (name: string, attribute = false): string => {
      if (!name.includes(':')) return attribute ? '' : namespaces[''] ?? '';
      const ns = namespaces[name.split(':')[0]];
      if (!ns) throw new WinrmError('xml', 'Unbound namespace prefix');
      return ns;
    };
    const expanded = new Set<string>();
    for (const [name, value] of rawAttrs) {
      if (name === 'xmlns' || name.startsWith('xmlns:')) continue;
      const ns = namespace(name, true);
      const key = `${ns}|${local(name)}`;
      if (expanded.has(key)) throw new WinrmError('xml', 'Duplicate expanded attribute');
      expanded.add(key);
      // Protocol attributes are unqualified. Never alias an attacker-controlled namespace.
      attrs[ns ? `{${ns}}${local(name)}` : name] = value;
    }
    const node: XmlNode = {
      name: local(head[1]),
      ns: namespace(head[1]),
      qname: head[1],
      namespaces,
      attrs,
      children: [],
      text: '',
    };
    if (parent) parent.children.push(node);
    else if (root) throw new WinrmError('xml', 'More than one root element');
    else root = node;
    if (!selfClosing) {
      if (stack.length >= XML_LIMITS.depth) throw new WinrmError('xml', 'Too deep');
      stack.push(node);
    }
  }
  if (stack.length || !root) throw new WinrmError('xml', 'Unclosed element');
  return root;
}

export function child(node: XmlNode | undefined, ...path: string[]): XmlNode | undefined {
  let current = node;
  for (const name of path) {
    const matches = current?.children.filter((c) => c.name === name) ?? [];
    if (matches.length > 1) throw new WinrmError('protocol', 'Duplicate response element');
    current = matches[0];
    if (current && current.ns !== elementNamespace(name)) {
      throw new WinrmError('protocol', 'Unexpected response namespace');
    }
    if (!current) return undefined;
  }
  return current;
}

export const xmlEscape = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

// ---------------------------------------------------------------------------------------------
// HTTP/1.1 over the raw TLS transport (single keep-alive connection)

export const HTTP_LIMITS = { header: 16 * 1024, body: 2 * 1024 * 1024 };

interface HttpResponse {
  status: number;
  contentType: string;
  body: string;
}

const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

/** Incremental response parser: Content-Length or chunked bodies, both bounded. */
class ResponseParser {
  #buffer = new Uint8Array(0);
  #head: { status: number; contentType: string; length: number | null; chunked: boolean } | null =
    null;
  #body: Uint8Array[] = [];
  #bodySize = 0;
  #chunk: number | null = null;
  #decoder = new TextDecoder('utf-8', { fatal: false });
  keepAlive = true;

  /** Returns a response when one is complete; throws on any violation. */
  push(chunk: Uint8Array): HttpResponse | null {
    this.#buffer = concat(this.#buffer, chunk);
    if (!this.#head) {
      const text = new TextDecoder('latin1').decode(
        this.#buffer.subarray(0, HTTP_LIMITS.header + 4),
      );
      const end = text.indexOf('\r\n\r\n');
      if (end < 0) {
        if (this.#buffer.length > HTTP_LIMITS.header) {
          throw new WinrmError('protocol', 'Oversized HTTP header');
        }
        return null;
      }
      if (end > HTTP_LIMITS.header) throw new WinrmError('protocol', 'Oversized HTTP header');
      this.#head = this.#parseHead(text.slice(0, end));
      this.#buffer = this.#buffer.subarray(end + 4);
    }
    const head = this.#head;
    if (head.chunked) return this.#readChunked(head);
    const length = head.length ?? 0;
    if (length > HTTP_LIMITS.body) throw new WinrmError('protocol', 'Oversized HTTP body');
    if (this.#buffer.length < length) return null;
    if (this.#buffer.length > length) throw new WinrmError('protocol', 'Unexpected extra data');
    return this.#done(head, this.#buffer.subarray(0, length));
  }

  #parseHead(text: string) {
    const lines = text.split('\r\n');
    const status = /^HTTP\/1\.1 (\d{3})(?: [^\r\n]*)?$/.exec(lines[0]);
    if (!status) throw new WinrmError('protocol', 'Not an HTTP/1.1 response');
    const headers = new Map<string, string>();
    for (const line of lines.slice(1)) {
      const m = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*?)[ \t]*$/.exec(line);
      if (!m) throw new WinrmError('protocol', 'Malformed HTTP header');
      const name = m[1].toLowerCase();
      if (headers.has(name) && (name === 'content-length' || name === 'transfer-encoding')) {
        throw new WinrmError('protocol', 'Duplicate framing header');
      }
      headers.set(name, m[2]);
    }
    const encoding = headers.get('transfer-encoding')?.toLowerCase() ?? null;
    const length = headers.get('content-length');
    if (encoding !== null && (encoding !== 'chunked' || length !== undefined)) {
      throw new WinrmError('protocol', 'Unsupported transfer framing');
    }
    if (length !== undefined && !/^\d{1,9}$/.test(length)) {
      throw new WinrmError('protocol', 'Invalid Content-Length');
    }
    if (encoding === null && length === undefined) {
      throw new WinrmError('protocol', 'Response without a length');
    }
    this.keepAlive = !/\bclose\b/i.test(headers.get('connection') ?? '');
    return {
      status: Number(status[1]),
      contentType: headers.get('content-type') ?? '',
      length: length === undefined ? null : Number(length),
      chunked: encoding === 'chunked',
    };
  }

  #readChunked(head: { status: number; contentType: string }): HttpResponse | null {
    for (;;) {
      if (this.#chunk === null) {
        const text = new TextDecoder('latin1').decode(this.#buffer.subarray(0, 40));
        const eol = text.indexOf('\r\n');
        if (eol < 0) {
          if (this.#buffer.length > 40) throw new WinrmError('protocol', 'Invalid chunk size');
          return null;
        }
        const size = /^([0-9a-fA-F]{1,8})(?:;[^\r\n]*)?$/.exec(text.slice(0, eol));
        if (!size) throw new WinrmError('protocol', 'Invalid chunk size');
        this.#chunk = parseInt(size[1], 16);
        this.#buffer = this.#buffer.subarray(eol + 2);
        if (this.#bodySize + this.#chunk > HTTP_LIMITS.body) {
          throw new WinrmError('protocol', 'Oversized HTTP body');
        }
      }
      if (this.#chunk === 0) {
        // Only the final CRLF may follow (no trailers).
        if (this.#buffer.length < 2) return null;
        if (this.#buffer[0] !== 13 || this.#buffer[1] !== 10 || this.#buffer.length > 2) {
          throw new WinrmError('protocol', 'Unsupported chunk trailer');
        }
        const all = new Uint8Array(this.#bodySize);
        let at = 0;
        for (const part of this.#body) {
          all.set(part, at);
          at += part.length;
        }
        return this.#done(head, all);
      }
      if (this.#buffer.length < this.#chunk + 2) return null;
      if (this.#buffer[this.#chunk] !== 13 || this.#buffer[this.#chunk + 1] !== 10) {
        throw new WinrmError('protocol', 'Invalid chunk');
      }
      this.#body.push(this.#buffer.slice(0, this.#chunk));
      this.#bodySize += this.#chunk;
      this.#buffer = this.#buffer.subarray(this.#chunk + 2);
      this.#chunk = null;
    }
  }

  #done(head: { status: number; contentType: string }, body: Uint8Array): HttpResponse {
    return {
      status: head.status,
      contentType: head.contentType,
      body: this.#decoder.decode(body),
    };
  }
}

/** One keep-alive HTTP connection; requests are strictly sequential. */
export class HttpConnection {
  #parser = new ResponseParser();
  #waiting: {
    resolve: (r: HttpResponse) => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  } | null = null;
  #closed: Error | null = null;
  #reuse = true;

  constructor(
    private readonly transport: ApiTransport,
    private readonly hostHeader: string,
    private readonly authorization: string,
  ) {
    transport.onData((chunk) => {
      const waiting = this.#waiting;
      if (!waiting) {
        // Data nobody asked for: the stream is out of sync.
        this.#fail(new WinrmError('protocol', 'Unsolicited data'));
        return;
      }
      let response: HttpResponse | null;
      try {
        response = this.#parser.push(chunk);
      } catch (error) {
        this.#fail(error as Error);
        return;
      }
      if (!response) return;
      clearTimeout(waiting.timer);
      this.#waiting = null;
      this.#reuse = this.#parser.keepAlive;
      this.#parser = new ResponseParser();
      waiting.resolve(response);
    });
    transport.onClose((error) =>
      this.#fail(
        error
          ? new WinrmError('closed', 'Connection error')
          : new WinrmError('closed', 'Connection closed'),
      )
    );
  }

  #fail(error: Error) {
    const first = this.#closed === null;
    this.#closed ??= error;
    const waiting = this.#waiting;
    this.#waiting = null;
    if (waiting) {
      clearTimeout(waiting.timer);
      waiting.reject(error);
    }
    if (first) this.transport.close();
  }

  get usable() {
    return !this.#closed && this.#reuse;
  }

  /** POST /wsman with the SOAP body. Redirects and non-SOAP answers are errors, never followed. */
  request(body: string, timeoutMs: number): Promise<{ status: number; body: string }> {
    if (this.#closed) return Promise.reject(this.#closed);
    if (!this.#reuse) {
      return Promise.reject(new WinrmError('closed', 'Connection closed by server'));
    }
    if (this.#waiting) return Promise.reject(new WinrmError('protocol', 'Request in progress'));
    const payload = new TextEncoder().encode(body);
    const head = new TextEncoder().encode(
      `POST /wsman HTTP/1.1\r\nHost: ${this.hostHeader}\r\nAuthorization: ${this.authorization}\r\n` +
        `Content-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: ${payload.length}\r\n` +
        `Connection: Keep-Alive\r\nUser-Agent: MNSCloud-AccessGateway\r\n\r\n`,
    );
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#fail(new WinrmError('timeout', 'The device did not answer in time'));
      }, timeoutMs);
      this.#waiting = {
        resolve: (response) => {
          if (response.status === 401 || response.status === 403) {
            reject(new WinrmError('auth_failed', 'The device refused the credential'));
            this.#fail(new WinrmError('auth_failed', 'Authentication failed'));
          } else if (response.status >= 300 && response.status < 400) {
            // Never follow a redirect: it could move the credential to another destination.
            reject(new WinrmError('redirect', 'The device answered with a redirect'));
            this.#fail(new WinrmError('redirect', 'redirect'));
          } else if (response.status === 200 || response.status === 500) {
            if (!/^application\/soap\+xml/i.test(response.contentType)) {
              reject(new WinrmError('protocol', 'Not a SOAP response'));
              this.#fail(new WinrmError('protocol', 'Not a SOAP response'));
            } else resolve({ status: response.status, body: response.body });
          } else {
            reject(
              new WinrmError('http_status', `HTTP ${response.status}`, String(response.status)),
            );
          }
        },
        reject,
        timer,
      };
      try {
        this.transport.write(concat(head, payload));
      } catch {
        this.#fail(new WinrmError('closed', 'Connection write failed'));
      }
    });
  }

  close() {
    this.#fail(new WinrmError('closed', 'Closed'));
  }
}

// ---------------------------------------------------------------------------------------------
// WS-Man / WinRS

const NS = {
  s: 'http://www.w3.org/2003/05/soap-envelope', // NOSONAR namespace identifier, not a URL that is fetched
  a: 'http://schemas.xmlsoap.org/ws/2004/08/addressing', // NOSONAR namespace identifier, not a URL that is fetched
  w: 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd', // NOSONAR namespace identifier, not a URL that is fetched
  p: 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd', // NOSONAR namespace identifier, not a URL that is fetched
  rsp: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell', // NOSONAR namespace identifier, not a URL that is fetched
  transfer: 'http://schemas.xmlsoap.org/ws/2004/09/transfer', // NOSONAR namespace identifier, not a URL that is fetched
  fault: 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault', // NOSONAR namespace identifier, not a URL that is fetched
};
function elementNamespace(name: string): string {
  if (
    ['Envelope', 'Header', 'Body', 'Fault', 'Detail', 'Code', 'Subcode', 'Value'].includes(name)
  ) return NS.s;
  if (['Action', 'RelatesTo', 'ReferenceParameters'].includes(name)) return NS.a;
  if (['SelectorSet', 'Selector'].includes(name)) return NS.w;
  if (name === 'ResourceCreated') return NS.transfer;
  if (name === 'WSManFault') return NS.fault;
  return NS.rsp;
}

export const SHELL_URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'; // NOSONAR namespace identifier, not a URL that is fetched
const ACTION = {
  create: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create', // NOSONAR namespace identifier, not a URL that is fetched
  delete: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete', // NOSONAR namespace identifier, not a URL that is fetched
  command: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command', // NOSONAR namespace identifier, not a URL that is fetched
  receive: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive', // NOSONAR namespace identifier, not a URL that is fetched
  signal: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal', // NOSONAR namespace identifier, not a URL that is fetched
};
const SIGNAL_TERMINATE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate'; // NOSONAR namespace identifier, not a URL that is fetched
const STATE_DONE = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done'; // NOSONAR namespace identifier, not a URL that is fetched
const GUID = /^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/;
/** WSMan fault code of an operation that ran out of its OperationTimeout (no data yet). */
const FAULT_TIMEOUT = '2150858793';

export interface Chunk {
  stream: 'stdout' | 'stderr';
  bytes: Uint8Array;
}

export interface ReceiveResult {
  chunks: Chunk[];
  done: boolean;
  exitCode: number | null;
}

/** The only WS-Man operations the gateway issues. */
export class WsmanClient {
  constructor(
    private readonly http: HttpConnection,
    private readonly toAddress: string,
    private readonly requestTimeoutMs = 20000,
  ) {}

  async #call(
    action: string,
    body: string,
    options: {
      shellId?: string;
      operationSeconds?: number;
      optionSet?: string;
      timeoutMs?: number;
    } = {},
  ): Promise<{ root: XmlNode; body: XmlNode | undefined; fault: string | null }> {
    const shellId = xmlEscape(options.shellId ?? '');
    const messageId = `uuid:${crypto.randomUUID().toUpperCase()}`;
    const operation = options.operationSeconds ?? 20;
    // Interpolated into the XML: only a bounded integer (never text) and escaped identifiers.
    if (!Number.isInteger(operation) || operation < 1 || operation > 600) {
      throw new WinrmError('protocol', 'Invalid operation timeout');
    }
    const xml = `<?xml version="1.0" encoding="UTF-8"?>` +
      `<s:Envelope xmlns:s="${NS.s}" xmlns:a="${NS.a}" xmlns:w="${NS.w}" xmlns:p="${NS.p}" xmlns:rsp="${NS.rsp}">` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<s:Header><a:To>${xmlEscape(this.toAddress)}</a:To>` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<w:ResourceURI s:mustUnderstand="true">${SHELL_URI}</w:ResourceURI>` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>` + // NOSONAR namespace identifier, not a URL that is fetched
      `<a:Action s:mustUnderstand="true">${action}</a:Action>` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>` +
      `<a:MessageID>${messageId}</a:MessageID>` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      `<w:Locale xml:lang="en-US" s:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>` +
      `<w:OperationTimeout>PT${operation}S</w:OperationTimeout>` + // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      (options.shellId
        ? `<w:SelectorSet><w:Selector Name="ShellId">${shellId}</w:Selector></w:SelectorSet>` // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
        : '') +
      (options.optionSet ?? '') + `</s:Header><s:Body>${body}</s:Body></s:Envelope>`; // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
    const response = await this.http.request(
      xml,
      Math.max(
        1,
        Math.min(this.requestTimeoutMs, options.timeoutMs ?? Infinity, (operation + 10) * 1000),
      ),
    );
    const root = parseXml(response.body);
    if (root.name !== 'Envelope' || root.ns !== NS.s) {
      throw new WinrmError('protocol', 'Not a SOAP envelope');
    }
    const relates = child(root, 'Header', 'RelatesTo')?.text.trim();
    if (relates !== messageId) {
      throw new WinrmError('protocol', 'Response does not match the request');
    }
    const bodyNode = child(root, 'Body');
    if (!bodyNode) throw new WinrmError('protocol', 'Missing SOAP body');
    const responseAction = child(root, 'Header', 'Action')?.text.trim();
    const fault = child(bodyNode, 'Fault');
    if (fault) {
      if (
        !['http://schemas.dmtf.org/wbem/wsman/1/wsman/fault', `${NS.a}/fault`].includes( // NOSONAR namespace identifier, not a URL that is fetched
          responseAction ?? '',
        )
      ) {
        throw new WinrmError('protocol', 'Invalid fault action');
      }
      if (bodyNode.children.length !== 1) throw new WinrmError('protocol', 'Ambiguous fault body');
      const code = child(fault, 'Detail', 'WSManFault')?.attrs.Code;
      // Only the documented timeout is distinguished; arbitrary numeric codes can carry secrets too.
      const safeCode = code === FAULT_TIMEOUT ? FAULT_TIMEOUT : 'unknown';
      return { root, body: bodyNode, fault: safeCode };
    }
    if (responseAction !== `${action}Response`) {
      throw new WinrmError('protocol', 'Invalid response action');
    }
    if (response.status !== 200) throw new WinrmError('http_status', `HTTP ${response.status}`);
    return { root, body: bodyNode, fault: null };
  }

  #require(fault: string | null) {
    if (fault !== null) throw new WinrmError('fault', 'The device answered with a fault', fault);
  }

  async createShell(): Promise<string> {
    const r = await this.#call(
      ACTION.create,
      `<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`,
      {
        optionSet:
          `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">TRUE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`,
      },
    );
    this.#require(r.fault);
    const direct = child(r.body, 'Shell', 'ShellId')?.text.trim();
    const selectorSet = child(r.body, 'ResourceCreated', 'ReferenceParameters', 'SelectorSet');
    const selector = child(selectorSet, 'Selector');
    if (selector && !['ShellId', 'ShellID'].includes(selector.attrs.Name)) {
      throw new WinrmError('protocol', 'Invalid shell selector');
    }
    const selected = selector?.text.trim();
    if (direct && selected && direct.toLowerCase() !== selected.toLowerCase()) {
      throw new WinrmError('protocol', 'Conflicting ShellId');
    }
    const id = direct ?? selected;
    if (!id || !GUID.test(id)) throw new WinrmError('protocol', 'Missing or invalid ShellId');
    return id;
  }

  async startCommand(shellId: string, commandLine: string, timeoutMs?: number): Promise<string> {
    const r = await this.#call(
      ACTION.command,
      `<rsp:CommandLine><rsp:Command>${xmlEscape(commandLine)}</rsp:Command></rsp:CommandLine>`, // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      {
        shellId,
        timeoutMs,
        optionSet:
          `<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option></w:OptionSet>`,
      },
    );
    this.#require(r.fault);
    const id = child(r.body, 'CommandResponse', 'CommandId')?.text.trim();
    if (!id || !GUID.test(id)) throw new WinrmError('protocol', 'Missing or invalid CommandId');
    return id;
  }

  /** One Receive: output so far, or none when the operation timeout elapsed on the device. */
  async receive(
    shellId: string,
    commandId: string,
    operationSeconds = 5,
    timeoutMs?: number,
  ): Promise<ReceiveResult> {
    const id = xmlEscape(commandId);
    const r = await this.#call(
      ACTION.receive,
      `<rsp:Receive><rsp:DesiredStream CommandId="${id}">stdout stderr</rsp:DesiredStream></rsp:Receive>`, // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      { shellId, operationSeconds, timeoutMs },
    );
    if (r.fault === FAULT_TIMEOUT) return { chunks: [], done: false, exitCode: null };
    this.#require(r.fault);
    const response = child(r.body, 'ReceiveResponse');
    if (!response) throw new WinrmError('protocol', 'Missing ReceiveResponse');
    const chunks: Chunk[] = [];
    let done = false;
    let exitCode: number | null = null;
    child(response, 'CommandState'); // singleton; repeated Stream elements are allowed.
    for (const node of response.children) {
      if (node.ns !== NS.rsp) throw new WinrmError('protocol', 'Unexpected stream namespace');
      if (node.name === 'Stream') {
        if (node.attrs.CommandId !== commandId) {
          throw new WinrmError('protocol', 'Output of another command');
        }
        const name = node.attrs.Name;
        if (name !== 'stdout' && name !== 'stderr') {
          throw new WinrmError('protocol', 'Unknown stream');
        }
        chunks.push({ stream: name, bytes: decodeBase64(node.text) });
      } else if (node.name === 'CommandState') {
        if (node.attrs.CommandId !== commandId) {
          throw new WinrmError('protocol', 'State of another command');
        }
        if (node.attrs.State === STATE_DONE) {
          done = true;
          const code = child(node, 'ExitCode')?.text.trim();
          if (code !== undefined) {
            if (!/^-?\d{1,10}$/.test(code)) throw new WinrmError('protocol', 'Invalid ExitCode');
            exitCode = Number(code);
          }
        }
      }
    }
    return { chunks, done, exitCode };
  }

  async terminate(shellId: string, commandId: string, timeoutMs = 2000): Promise<void> {
    const id = xmlEscape(commandId);
    const r = await this.#call(
      ACTION.signal,
      `<rsp:Signal CommandId="${id}"><rsp:Code>${SIGNAL_TERMINATE}</rsp:Code></rsp:Signal>`, // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, interpolations are constants or escaped
      { shellId, operationSeconds: 5, timeoutMs },
    );
    this.#require(r.fault);
  }

  async deleteShell(shellId: string): Promise<void> {
    const r = await this.#call(ACTION.delete, '', {
      shellId,
      operationSeconds: 5,
      timeoutMs: 2000,
    });
    this.#require(r.fault);
  }
}

/** Strict base64 (no whitespace tricks beyond line breaks the server may add). */
export function decodeBase64(text: string): Uint8Array {
  const clean = text.replace(/[\r\n\t ]/g, '');
  if (clean.length > HTTP_LIMITS.body) throw new WinrmError('protocol', 'Oversized stream');
  if (!clean) return new Uint8Array(0);
  if (clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new WinrmError('protocol', 'Invalid base64 stream');
  }
  const bytes = Buffer.from(clean, 'base64');
  if (bytes.toString('base64') !== clean) {
    throw new WinrmError('protocol', 'Noncanonical base64 stream');
  }
  return new Uint8Array(bytes);
}

export function basicAuthorization(username: string, password: string): string {
  return 'Basic ' + Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
}

/** `ip` or `[ipv6]` with the port, the way the Host header and the To address name the device. */
export function hostAuthority(address: string, port: number): string {
  return `${address.includes(':') ? `[${address}]` : address}:${port}`;
}

/**
 * Runs one command in an open shell: Command -> Receive* (bounded by bytes and time) -> on any
 * early end Signal(terminate). Output chunks are handed to `onChunk` as they arrive; throwing from
 * it (output limit) ends the command the same way.
 */
export async function runWinrmCommand(
  client: WsmanClient,
  shellId: string,
  commandLine: string,
  options: {
    timeoutMs: number;
    maxBytes: number;
    onChunk(chunk: Chunk): void;
    /** True when the request was cancelled (checked between receives). */
    cancelled(): boolean;
  },
): Promise<{ exitCode: number | null; timedOut: boolean; cancelled: boolean; truncated: boolean }> {
  const deadline = Date.now() + Math.max(0, options.timeoutMs);
  const result = (timedOut = false, cancelled = false, truncated = false) => ({
    exitCode: null,
    timedOut,
    cancelled,
    truncated,
  });
  if (options.cancelled()) return result(false, true);
  if (Date.now() >= deadline) return result(true);
  let commandId: string | null = null;
  let bytes = 0;
  let truncated = false;
  const stop = async (): Promise<void> => {
    if (!commandId) return;
    try {
      await client.terminate(shellId, commandId, 2000);
    } catch { /* Delete follows, or the bounded transport has already closed. */ }
  };
  try {
    commandId = await client.startCommand(shellId, commandLine, deadline - Date.now());
    for (let round = 0; round < 100000; round++) {
      if (options.cancelled()) {
        await stop();
        return result(false, true, truncated);
      }
      if (Date.now() >= deadline) {
        await stop();
        return result(true, false, truncated);
      }
      const remaining = deadline - Date.now();
      // Do not start a one-second WS-Man receive when less than its operation window remains.
      if (remaining < Math.min(1000, options.timeoutMs / 10)) {
        await stop();
        return result(true, false, truncated);
      }
      const seconds = Math.max(1, Math.min(5, Math.floor(remaining / 1000)));
      const part = await client.receive(shellId, commandId, seconds, remaining);
      // A late or cancelled response must never publish output or report success.
      if (options.cancelled()) {
        await stop();
        return result(false, true, truncated);
      }
      if (Date.now() >= deadline) {
        await stop();
        return result(true, false, truncated);
      }
      for (const chunk of part.chunks) {
        if (options.cancelled()) {
          await stop();
          return result(false, true, truncated);
        }
        bytes += chunk.bytes.length;
        if (bytes > options.maxBytes) {
          truncated = true;
          const room = Math.max(0, options.maxBytes - (bytes - chunk.bytes.length));
          if (room) options.onChunk({ stream: chunk.stream, bytes: chunk.bytes.subarray(0, room) });
          await stop();
          return result(false, false, truncated);
        }
        options.onChunk(chunk);
      }
      if (part.done) {
        return { exitCode: part.exitCode, timedOut: false, cancelled: false, truncated };
      }
    }
    throw new WinrmError('protocol', 'Too many receive rounds');
  } catch (error) {
    await stop();
    if (options.cancelled()) return result(false, true, truncated);
    if (Date.now() >= deadline || error instanceof WinrmError && error.code === 'timeout') {
      return result(true, false, truncated);
    }
    throw error;
  }
}
