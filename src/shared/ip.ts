// IP literal and CIDR helpers. The gateway never resolves names: every address it handles is an
// IP literal chosen by the API (which resolves with a rebinding guard), and the gateway checks it
// again against the denylist before building a session.

export type Family = 4 | 6;

export interface ParsedAddress {
  family: Family;
  value: bigint;
  text: string;
}

export interface Cidr {
  family: Family;
  base: bigint;
  prefix: number;
  text: string;
}

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function parseV4(text: string): bigint | null {
  if (!V4.test(text)) return null;
  return text.split('.').reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

function parseV6(text: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || text.length > 45) return null;
  let head = text;
  let tailV4: bigint | null = null;
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.')) {
    tailV4 = parseV4(text.slice(lastColon + 1));
    if (tailV4 === null) return null;
    head = text.slice(0, lastColon + 1) + '0:0';
  }
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (halves.length === 1 && left.length !== 8) return null;
  if (halves.length === 2 && groups < 1) return null;
  const all = [...left, ...Array(groups).fill('0'), ...right];
  if (all.length !== 8) return null;
  let value = 0n;
  for (const group of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  if (tailV4 !== null) value = (value & ~0xffffffffn) | tailV4;
  return value;
}

/** Parses an IP literal (no brackets, no zone index). */
export function parseAddress(text: unknown): ParsedAddress | null {
  if (typeof text !== 'string') return null;
  const v4 = parseV4(text);
  if (v4 !== null) return { family: 4, value: v4, text };
  const v6 = parseV6(text);
  if (v6 !== null) return { family: 6, value: v6, text: formatV6(v6) };
  return null;
}

export function formatV4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 0xffn)).join('.');
}

export function formatV6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  // Longest run of zero groups (length >= 2) becomes "::" (RFC 5952).
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) [best, bestLen] = [i, j - i];
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

export function formatAddress(family: Family, value: bigint): string {
  return family === 4 ? formatV4(value) : formatV6(value);
}

function bits(family: Family) {
  return family === 4 ? 32 : 128;
}

/** Parses "a.b.c.d/n" or "x::/n" (a bare address is a host route). Host bits must be zero. */
export function parseCidr(text: unknown): Cidr | null {
  if (typeof text !== 'string') return null;
  const [addressText, prefixText, extra] = text.trim().split('/');
  if (extra !== undefined) return null;
  const address = parseAddress(addressText);
  if (!address) return null;
  const width = bits(address.family);
  const prefix = prefixText === undefined ? width : Number(prefixText);
  if (!/^\d{1,3}$/.test(prefixText ?? String(width)) || prefix < 0 || prefix > width) return null;
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(width - prefix);
  if ((address.value & ~mask & ((1n << BigInt(width)) - 1n)) !== 0n) return null;
  return {
    family: address.family,
    base: address.value,
    prefix,
    text: `${formatAddress(address.family, address.value)}/${prefix}`,
  };
}

export function cidrContains(cidr: Cidr, address: ParsedAddress): boolean {
  if (cidr.family !== address.family) return false;
  const width = bits(cidr.family);
  const shift = BigInt(width - cidr.prefix);
  return (address.value >> shift) === (cidr.base >> shift);
}

/** Address `offset` positions after the network base of `cidr`. */
export function cidrOffset(cidr: Cidr, offset: bigint): bigint {
  const size = 1n << BigInt(bits(cidr.family) - cidr.prefix);
  if (offset < 0n || offset >= size) throw new RangeError('Offset outside the range');
  return cidr.base + offset;
}
