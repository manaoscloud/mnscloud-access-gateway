/** Strict, bounded XML subset for protocol envelopes; no external resources or parser dependencies. */
export interface Element {
  name: string;
  ns: string;
  attrs: Map<string, string>;
  children: Element[];
  text: string;
}
export class ProtocolError extends Error {
  constructor(readonly code = 'PROTOCOL') {
    super(code);
  }
}
export const MAX_FRAME = 1024 * 1024;
const XML = 'http://www.w3.org/XML/1998/namespace';
const NAME = /^[A-Za-z_][A-Za-z0-9_.-]*(?::[A-Za-z_][A-Za-z0-9_.-]*)?$/;
export function escapeXml(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&apos;',
    }[c]!),
  );
}
function decode(s: string): string {
  if (
    s.replace(/&(?:amp|lt|gt|quot|apos|#\d{1,7}|#x[0-9a-fA-F]{1,6});/g, '')
      .includes('&')
  ) throw new ProtocolError();
  const value = s.replace(/&([^;]+);/g, (_, x: string) => {
    const named: Record<string, string> = {
      amp: '&',
      lt: '<',
      gt: '>',
      quot: '"',
      apos: "'",
    };
    if (x in named) return named[x];
    const n = x.startsWith('#x') ? parseInt(x.slice(2), 16) : Number(x.slice(1));
    if (
      !(n === 9 || n === 10 || n === 13 || n >= 32 && n <= 0xd7ff ||
        n >= 0xe000 && n <= 0xfffd || n >= 0x10000 && n <= 0x10ffff)
    ) throw new ProtocolError();
    return String.fromCodePoint(n);
  });
  // deno-lint-ignore no-control-regex
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]/.test(value)) {
    throw new ProtocolError();
  }
  return value;
}
export function parseXml(bytes: Uint8Array): Element {
  if (bytes.length > MAX_FRAME) throw new ProtocolError('FRAME_LIMIT');
  let s: string;
  try {
    s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ProtocolError();
  }
  s = s.replace(
    /^\s*<\?xml\s+version=(?:"1\.0"|'1\.0')(?:\s+encoding=(?:"UTF-8"|'UTF-8'))?\s*\?>/,
    '',
  );
  if (/<!|<\?/.test(s)) throw new ProtocolError();
  const stack: { el: Element; q: string; namespaces: Map<string, string> }[] = [];
  let root: Element | undefined;
  let i = 0, count = 0;
  while (i < s.length) {
    if (s[i] !== '<') {
      const j = s.indexOf('<', i);
      const text = decode(s.slice(i, j < 0 ? s.length : j));
      if (!stack.length) { if (text.trim()) throw new ProtocolError(); }
      else stack.at(-1)!.el.text += text;
      i = j < 0 ? s.length : j;
      continue;
    }
    let quote = '', j = i + 1;
    for (; j < s.length; j++) {
      const c = s[j];
      if (quote) { if (c === quote) quote = ''; }
      else if (c === '"' || c === "'") quote = c;
      else if (c === '>') break;
    }
    if (j === s.length) throw new ProtocolError();
    const tag = s.slice(i + 1, j);
    i = j + 1;
    if (tag.startsWith('/')) {
      const q = tag.slice(1).trim();
      if (!NAME.test(q) || !stack.length || stack.pop()!.q !== q) {
        throw new ProtocolError();
      }
      continue;
    }
    const self = tag.endsWith('/');
    const raw = self ? tag.slice(0, -1) : tag;
    const m = /^([^\s]+)([\s\S]*)$/.exec(raw);
    if (!m || !NAME.test(m[1])) throw new ProtocolError();
    const ns = new Map(stack.at(-1)?.namespaces ?? [['xml', XML]]);
    const attrs = new Map<string, string>();
    let rest = m[2];
    let n = 0;
    while (rest.trim()) {
      const a = /^\s+([^\s=]+)\s*=\s*(["'])([^]*?)\2/.exec(rest);
      if (
        !a || !NAME.test(a[1]) || a[3].includes('<') || attrs.has(a[1]) ||
        ++n > 32
      ) throw new ProtocolError();
      attrs.set(a[1], decode(a[3]));
      rest = rest.slice(a[0].length);
    }
    for (const [k, v] of attrs) {
      if (k === 'xmlns' || k.startsWith('xmlns:')) {
        const p = k === 'xmlns' ? '' : k.slice(6);
        if (
          p === 'xmlns' || p === 'xml' && v !== XML || p !== '' && !v ||
          v === 'http://www.w3.org/2000/xmlns/' || v === XML && p !== 'xml'
        ) throw new ProtocolError();
        ns.set(p, v);
      }
    }
    const expand = (q: string, attribute = false): [string, string] => {
      const p = q.includes(':') ? q.split(':')[0] : '';
      if (p && !ns.has(p)) throw new ProtocolError();
      return [
        q.split(':').at(-1)!,
        p ? ns.get(p)! : attribute ? '' : ns.get('') ?? '',
      ];
    };
    const [name, uri] = expand(m[1]);
    const el: Element = {
      name,
      ns: uri,
      attrs: new Map(),
      children: [],
      text: '',
    };
    for (const [k, v] of attrs) {
      if (k === 'xmlns' || k.startsWith('xmlns:')) continue;
      const [a, u] = expand(k, true), key = `{${u}}${a}`;
      if (el.attrs.has(key)) throw new ProtocolError();
      el.attrs.set(key, v);
    }
    if (++count > 8000 || stack.length >= 32) {
      throw new ProtocolError('XML_LIMIT');
    }
    if (stack.length) stack.at(-1)!.el.children.push(el);
    else {
      if (root) throw new ProtocolError();
      root = el;
    }
    if (!self) stack.push({ el, q: m[1], namespaces: ns });
  }
  if (stack.length || !root) throw new ProtocolError();
  return root;
}
export function only(parent: Element, name: string, ns: string): Element {
  const c = parent.children.filter((x) => x.name === name && x.ns === ns);
  if (c.length !== 1) throw new ProtocolError();
  return c[0];
}
export function is(el: Element, name: string, ns: string): boolean {
  return el.name === name && el.ns === ns;
}
