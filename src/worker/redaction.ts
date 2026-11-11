// Output redaction (assessment 7.1 A5). Runs in the worker before anything leaves it (WebSocket,
// recording, command events). Device output is buffered per line; a partial line (prompts, echo)
// is flushed after a short delay, but any suffix that could still become a secret is held back:
// a prefix of a session secret literal, an unterminated "password=" value, or the start of a
// PRIVATE KEY block. Matching ignores interleaved ANSI CSI sequences (RouterOS colors its echo).

import type { RedactPattern } from './rules.ts';

export const MASK = '********';
const MAX_HOLD = 4096;
const KEY_BLOCK_START = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const KEY_BLOCK_END = /-----END [A-Z0-9 ]*PRIVATE KEY-----/;
const KEY_BLOCK_PREFIX = '-----BEGIN';
const CRYPT_HASH = /\$(?:1|2[abxy]?|5|6|y|gy|7|sha1|md5)\$[^\s:'"]{8,}/g;
// deno-lint-ignore no-control-regex
const ANSI = /\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g;

interface Stripped {
  text: string;
  map: number[]; // map[i] = index in the original of text[i]; map[text.length] = original length
}

export function stripAnsi(input: string): Stripped {
  const map: number[] = [];
  let text = '';
  let last = 0;
  ANSI.lastIndex = 0;
  for (let m = ANSI.exec(input); m; m = ANSI.exec(input)) {
    for (let i = last; i < m.index; i++) {
      map.push(i);
      text += input[i];
    }
    last = m.index + m[0].length;
  }
  for (let i = last; i < input.length; i++) {
    map.push(i);
    text += input[i];
  }
  map.push(input.length);
  return { text, map };
}

interface Range {
  start: number;
  end: number;
}

function mergeRanges(ranges: Range[]): Range[] {
  ranges.sort((a, b) => a.start - b.start);
  const out: Range[] = [];
  for (const range of ranges) {
    const last = out[out.length - 1];
    if (last && range.start <= last.end) last.end = Math.max(last.end, range.end);
    else out.push({ ...range });
  }
  return out;
}

function escapeRegex(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Words that start a secret key; a trailing token that may still grow into one is held back.
const KEY_WORDS = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'psk',
  'pre-shared-key',
  'presharedkey',
  'privatekey',
  'private-key',
  'private_key',
  'key',
  'key-string',
  'community',
  'token',
  'cipher',
  'irreversible-cipher',
  'simple',
  'sha',
  'md5',
  'hmac-sha256',
  'auth-key',
  'authentication-key',
  'api-key',
  'access-key',
  'client-secret',
  'enable',
  '-----begin',
];

/** Index from which the last token is held back (it may still become a key, hash or URL secret). */
export function heldToken(text: string): number {
  const match = /\S*$/.exec(text)!;
  const token = match[0].toLowerCase();
  if (!token) {
    // "PrivateKey = ..." / "password 7 ...": a key word followed by spaces still awaits its value.
    const previous = /(\S+)\s+$/.exec(text);
    const word = previous?.[1].toLowerCase() ?? '';
    return word && KEY_WORDS.some((key) => word.endsWith(key)) ? previous!.index : text.length;
  }
  if (/[=:]["']?$/.test(token) || /[a-z][a-z0-9+.-]*:\/+[^@\s]*$/.test(token)) return match.index;
  const crypt = /\$[0-9a-z]{0,6}(?:\$[^\s:]*)?$/.exec(token);
  if (crypt) return match.index + crypt.index;
  const cipher = /%[\^@$#]*\S*$/.exec(token);
  if (cipher) return match.index + cipher.index;
  for (let n = token.length; n > 0; n--) {
    const suffix = token.slice(token.length - n);
    if (KEY_WORDS.some((word) => word.startsWith(suffix))) return match.index;
  }
  return text.length;
}

export class Redactor {
  #patterns: RedactPattern[];
  #literals: string[] = [];
  #literalRegex: RegExp | null = null;
  #buffer = '';
  #inKeyBlock = false;
  #continueValue = false;

  constructor(patterns: RedactPattern[]) {
    this.#patterns = patterns;
  }

  /** Adds the session's own secret (password, passphrase, key lines) as a literal to mask. */
  addSecret(secret: string | undefined) {
    if (!secret) return;
    const parts = secret.includes('\n')
      ? secret.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length >= 8)
      : [secret];
    for (const part of parts) {
      if (part.length >= 3 && !this.#literals.includes(part)) this.#literals.push(part);
    }
    this.#literals.sort((a, b) => b.length - a.length);
    this.#literalRegex = this.#literals.length
      ? new RegExp(this.#literals.map(escapeRegex).join('|'), 'g')
      : null;
  }

  /** Ranges (in stripped text) that must be masked. `open` reports an unterminated value. */
  #ranges(text: string): { ranges: Range[]; openAt: number | null } {
    const ranges: Range[] = [];
    let openAt: number | null = null;
    for (const pattern of this.#patterns) {
      pattern.regex.lastIndex = 0;
      for (let m = pattern.regex.exec(text); m; m = pattern.regex.exec(text)) {
        const value = m.indices?.groups?.value;
        if (!value) {
          ranges.push({ start: m.index, end: m.index + m[0].length });
        } else {
          ranges.push({ start: value[0], end: value[1] });
          if (value[1] === text.length) {
            openAt = openAt === null ? m.index : Math.min(openAt, m.index);
          }
        }
        if (m[0].length === 0) pattern.regex.lastIndex++;
      }
    }
    CRYPT_HASH.lastIndex = 0;
    for (let m = CRYPT_HASH.exec(text); m; m = CRYPT_HASH.exec(text)) {
      ranges.push({ start: m.index, end: m.index + m[0].length });
    }
    if (this.#literalRegex) {
      this.#literalRegex.lastIndex = 0;
      for (let m = this.#literalRegex.exec(text); m; m = this.#literalRegex.exec(text)) {
        ranges.push({ start: m.index, end: m.index + m[0].length });
      }
    }
    return { ranges: mergeRanges(ranges), openAt };
  }

  /**
   * Start of a key whose value may still arrive: each pattern is tried on the text followed by a
   * probe character; a match whose value reaches the probe means the value is still open.
   */
  #openValueStart(text: string): number {
    let start = text.length;
    for (const probe of ['X', 'X"', "X'"]) {
      const probed = text + probe;
      for (const pattern of this.#patterns) {
        pattern.regex.lastIndex = 0;
        for (let m = pattern.regex.exec(probed); m; m = pattern.regex.exec(probed)) {
          const end = m.indices?.groups?.value?.[1] ?? m.index + m[0].length;
          if (end > text.length) start = Math.min(start, m.index);
          if (m[0].length === 0) pattern.regex.lastIndex++;
        }
      }
    }
    return start;
  }

  /** Masks one complete piece of text (used for lines and command events). */
  redactText(input: string): string {
    const { text, map } = stripAnsi(input);
    const { ranges } = this.#ranges(text);
    return applyRanges(input, map, ranges);
  }

  /** A value cut by a forced flush keeps being masked up to the next whitespace. */
  #continuation(text: string): { prefix: string; text: string } {
    if (!this.#continueValue) return { prefix: '', text };
    const value = /^[^\s"']*/.exec(text)![0];
    const rest = text.slice(value.length);
    this.#continueValue = rest.length === 0;
    return { prefix: value.length ? MASK : '', text: rest };
  }

  #redactLine(input: string): string {
    const { prefix, text: line } = this.#continuation(input);
    if (this.#inKeyBlock) {
      if (KEY_BLOCK_END.test(line)) {
        this.#inKeyBlock = false;
        return prefix + line.replace(/^.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)/, `${MASK}$1`);
      }
      return prefix + (line.endsWith('\n') ? `${MASK}\r\n` : '');
    }
    if (KEY_BLOCK_START.test(line)) {
      const startAt = line.search(KEY_BLOCK_START);
      const head = line.slice(0, startAt);
      const rest = line.slice(startAt);
      if (KEY_BLOCK_END.test(rest)) {
        return prefix + this.redactText(head) + rest.replace(
          /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)/s,
          `$1${MASK}$2`,
        );
      }
      this.#inKeyBlock = true;
      return prefix + this.redactText(head) +
        rest.replace(/(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*/s, `$1\r\n`);
    }
    return prefix + this.redactText(line);
  }

  /** Feeds device output; returns what is safe to emit now (complete lines only). */
  push(chunk: string): string {
    this.#buffer += chunk;
    let out = '';
    let index: number;
    while ((index = this.#buffer.indexOf('\n')) >= 0) {
      out += this.#redactLine(this.#buffer.slice(0, index + 1));
      this.#buffer = this.#buffer.slice(index + 1);
    }
    if (this.#buffer.length > MAX_HOLD) out += this.flush(true);
    return out;
  }

  /** Timed flush of the partial line, holding back anything that may still become a secret. */
  flush(force = false): string {
    if (!this.#buffer) return '';
    if (this.#inKeyBlock) {
      if (force) this.#buffer = '';
      return '';
    }
    // An escape sequence cut at the end of the chunk is held whole (it may hide a key).
    // deno-lint-ignore no-control-regex
    const partialEscape = force ? -1 : this.#buffer.search(/\x1b(?:\[[0-?]*[ -/]*)?$/);
    const visible = partialEscape >= 0 ? this.#buffer.slice(0, partialEscape) : this.#buffer;
    const { text, map } = stripAnsi(visible);
    let holdFrom = text.length;
    if (!force) {
      holdFrom = Math.min(holdFrom, this.#openValueStart(text), heldToken(text));
      for (const literal of this.#literals) {
        for (let n = Math.min(literal.length - 1, text.length); n > 0; n--) {
          if (text.endsWith(literal.slice(0, n))) {
            holdFrom = Math.min(holdFrom, text.length - n);
            break;
          }
        }
      }
      for (let n = Math.min(KEY_BLOCK_PREFIX.length + 40, text.length); n > 0; n--) {
        const tail = text.slice(text.length - n);
        if (KEY_BLOCK_PREFIX.startsWith(tail) || tail.startsWith(KEY_BLOCK_PREFIX)) {
          holdFrom = Math.min(holdFrom, text.length - n);
          break;
        }
      }
    }
    const cut = map[holdFrom];
    const emit = this.#buffer.slice(0, cut);
    const keep = this.#buffer.slice(cut);
    const openAtEnd = force && this.#ranges(text).openAt !== null;
    this.#buffer = keep;
    const out = emit ? this.#redactPartial(emit) : '';
    if (openAtEnd) this.#continueValue = true;
    return out;
  }

  #redactPartial(input: string): string {
    if (KEY_BLOCK_START.test(input)) return this.#redactLine(input);
    const { prefix, text } = this.#continuation(input);
    return prefix + this.redactText(text);
  }

  /** Everything left at the end of the session (masked as a whole). */
  end(): string {
    const rest = this.#buffer;
    this.#buffer = '';
    if (this.#inKeyBlock) return '';
    return rest ? this.redactText(rest) : '';
  }
}

function applyRanges(input: string, map: number[], ranges: Range[]): string {
  if (!ranges.length) return input;
  let out = '';
  let last = 0;
  for (const range of ranges) {
    const start = map[range.start];
    const end = map[range.end - 1] + 1;
    out += input.slice(last, start) + MASK;
    last = end;
  }
  return out + input.slice(last);
}
