// Manual-mode input gate. Keystrokes reach the device immediately (the device echoes them), but
// Enter is held until the shadow line buffer is classified:
//   - read runs at once;
//   - writes wait for the operator to confirm the reconstructed line in the App ("4:" frame);
//   - destructive needs two confirmations; secret_read and what the level forbids are blocked
//     and the device line is cleared with the dialect's cancel key.
// Input the buffer cannot follow (arrows, Tab, history, other escapes, dialect help keys) taints
// the line: its Enter is classified as unknown -> write_risky (fail-closed).

import type { CommandClass, ConfirmMessage, ControlMessage } from '../shared/framing.ts';
import type { CommandEvent, SupportLevel } from '../shared/ipc.ts';
import type { Classifier } from './classifier.ts';
import { blockHint, decide } from './policy.ts';

const MAX_LINE = 4096;
const MAX_QUEUE = 64 * 1024;
const PASTE_START = '\x1b[200~';
const PASTE_END = '\x1b[201~';
// Terminal reports: the browser terminal (xterm.js) answers device queries through the keystroke
// channel. A report passes without tainting the line only when the device asked for it in its
// output (RouterOS asks the cursor position several times at login); any other one still taints.
const QUERIES: [RegExp, 'cpr' | 'da' | 'dsr'][] = [
  [/\x1b\[\??6n/g, 'cpr'],
  [/\x1bZ|\x1b\[[0>]?c/g, 'da'],
  [/\x1b\[5n/g, 'dsr'],
];
const REPORTS: [RegExp, 'cpr' | 'da' | 'dsr'][] = [
  [/^\x1b\[\??\d{1,4};\d{1,4}R$/, 'cpr'],
  [/^\x1b\[[?>][\d;]{0,32}c$/, 'da'],
  [/^\x1b\[0n$/, 'dsr'],
];
const MAX_OPEN_QUERIES = 16;

export interface GateSinks {
  toDevice(data: string): void;
  control(message: ControlMessage): void;
  event(event: CommandEvent): void;
  marker(label: string): void;
  redactLine(line: string): string;
}

interface Pending {
  id: string;
  line: string;
  class: CommandClass;
  unknown: boolean;
  rule: string | null;
  steps: 1 | 2;
  step: 1 | 2;
  timer: ReturnType<typeof setTimeout>;
  menu: string;
}

export class InputGate {
  #buffer = '';
  #tainted = false;
  #escape = '';
  #lastWasCr = false;
  #pending: Pending | null = null;
  #queue = '';
  #alternateScreen = false;
  #queries = { cpr: 0, da: 0, dsr: 0 };
  #outputTail = '';
  #counter = 0;

  constructor(
    private readonly classifier: Classifier,
    private readonly level: SupportLevel,
    private readonly sinks: GateSinks,
    private readonly verdictTimeoutSeconds = 120,
  ) {}

  /** Counts device queries (a query split across two chunks is joined by the kept tail). */
  #countQueries(data: string) {
    const text = this.#outputTail + data;
    for (const [pattern, kind] of QUERIES) {
      const found = text.match(pattern)?.length ?? 0;
      this.#queries[kind] = Math.min(MAX_OPEN_QUERIES, this.#queries[kind] + found);
    }
    // Keep only an unfinished escape at the end, never a query already counted.
    const last = text.lastIndexOf('\x1b');
    this.#outputTail = last >= 0 && text.length - last < 4 && !/[A-Za-z]/.test(text.slice(last + 1))
      ? text.slice(last)
      : '';
  }

  /** True when the sequence is a terminal report the device asked for (consumes one query). */
  #takeReport(sequence: string): boolean {
    const kind = REPORTS.find(([pattern]) => pattern.test(sequence))?.[1];
    if (!kind || this.#queries[kind] === 0) return false;
    this.#queries[kind]--;
    return true;
  }

  get line() {
    return this.#buffer;
  }

  get tainted() {
    return this.#tainted;
  }

  get pending() {
    return this.#pending ? { id: this.#pending.id, step: this.#pending.step } : null;
  }

  /** Device output hook: full-screen programs change how Enter is read. */
  observeOutput(data: string) {
    this.#countQueries(data);
    const on = data.lastIndexOf('\x1b[?1049h'), off = data.lastIndexOf('\x1b[?1049l');
    if (on < 0 && off < 0) return;
    const next = on > off;
    if (this.#alternateScreen && !next) {
      // Keys typed inside the program are not part of the next shell line.
      this.#buffer = '';
      this.#tainted = false;
    }
    this.#alternateScreen = next;
  }

  input(data: string) {
    data = this.#escape + data;
    this.#escape = '';
    let i = 0;
    while (i < data.length) {
      if (this.#pending) {
        // While a verdict is open only Ctrl+C passes (it cancels the held line).
        const rest = data.slice(i);
        const cancel = rest.indexOf('\x03');
        if (cancel >= 0) {
          this.#queue = '';
          this.#resolve('denied');
          this.sinks.toDevice('\x03');
          i += cancel + 1;
          continue;
        }
        if (this.#queue.length + rest.length <= MAX_QUEUE) this.#queue += rest;
        return;
      }
      const ch = data[i];
      if (ch === '\x1b') {
        const sequence = readEscape(data, i);
        if (sequence === null) {
          // Incomplete sequence at the end of the chunk: wait for the rest.
          this.#escape = data.slice(i);
          return;
        }
        i += sequence.length;
        if (sequence === PASTE_START || sequence === PASTE_END) continue; // pasted lines run one by one
        if (this.#takeReport(sequence)) {
          this.sinks.toDevice(sequence);
          continue;
        }
        this.#tainted = true;
        this.sinks.toDevice(sequence);
        continue;
      }
      i++;
      if (ch === '\n' && this.#lastWasCr) {
        this.#lastWasCr = false;
        continue;
      }
      this.#lastWasCr = ch === '\r';
      if (ch === '\r' || ch === '\n') {
        this.#enter();
        continue;
      }
      this.#track(ch);
      this.sinks.toDevice(ch);
    }
  }

  #track(ch: string) {
    const code = ch.codePointAt(0) ?? 0;
    if (this.classifier.rules.clearKeys.includes(ch)) {
      this.#buffer = '';
      this.#tainted = false;
      return;
    }
    if (code === 0x7f || code === 0x08) {
      this.#buffer = this.#buffer.slice(0, -1);
      return;
    }
    if (ch === '\x0c' || ch === '\x04' || ch === '\x1a') return; // clear screen, EOF, suspend
    if (code < 0x20 || (code >= 0x80 && code < 0xa0)) {
      this.#tainted = true;
      return;
    }
    if (this.classifier.rules.untrackable.includes(ch)) {
      this.#tainted = true;
      return;
    }
    if (this.#buffer.length >= MAX_LINE) {
      this.#tainted = true;
      return;
    }
    this.#buffer += ch;
  }

  #enter() {
    const line = this.#buffer;
    const tainted = this.#tainted;
    this.#buffer = '';
    this.#tainted = false;
    if (this.#alternateScreen && !line && !tainted) {
      this.sinks.toDevice('\r');
      return;
    }
    const classification = this.classifier.classify(line);
    const unknown = tainted || classification.unknown;
    const commandClass: CommandClass = tainted && classification.class !== 'secret_read' &&
        classification.class !== 'destructive' && classification.class !== 'pivot'
      ? 'write_risky'
      : classification.class;
    const rule = tainted ? 'tainted-input' : classification.rule;
    const shown = this.sinks.redactLine(line);
    const decision = decide(this.level, commandClass);
    const id = `v${++this.#counter}-${crypto.randomUUID().slice(0, 8)}`;
    if (decision === 'allow') {
      this.classifier.commit(classification);
      this.#emitEvent(shown, commandClass, unknown, 'allowed', rule);
      this.sinks.toDevice('\r');
      return;
    }
    if (decision === 'block') {
      this.sinks.toDevice(this.classifier.rules.cancelLine);
      this.#emitEvent(shown, commandClass, unknown, 'blocked', rule);
      this.sinks.control({
        type: 'blocked',
        id,
        line: shown,
        class: commandClass,
        unknown,
        hint: classification.hint ?? blockHint(this.level, commandClass, unknown),
      });
      return;
    }
    const steps = decision === 'double_confirm' ? 2 : 1;
    this.#pending = {
      id,
      line: shown,
      class: commandClass,
      unknown,
      rule,
      steps,
      step: 1,
      menu: classification.menu,
      timer: setTimeout(() => this.#resolve('expired'), this.verdictTimeoutSeconds * 1000),
    };
    this.#sendVerdict();
  }

  #sendVerdict() {
    const pending = this.#pending!;
    this.sinks.control({
      type: 'verdict',
      id: pending.id,
      line: pending.line,
      class: pending.class,
      unknown: pending.unknown,
      requires: pending.steps === 2 ? 'double_confirm' : 'confirm',
      step: pending.step,
      expiresInSeconds: this.verdictTimeoutSeconds,
    });
  }

  /** "4:" frame from the App. A confirmation must name the open verdict and its current step. */
  decide(message: ConfirmMessage) {
    const pending = this.#pending;
    if (!pending || message.id !== pending.id) return;
    if (message.type === 'deny') {
      this.#resolve('denied');
      return;
    }
    if ((message.step ?? 1) !== pending.step) return;
    if (pending.step < pending.steps) {
      pending.step = 2;
      this.#sendVerdict();
      return;
    }
    this.#resolve('confirmed');
  }

  #resolve(decision: 'confirmed' | 'denied' | 'expired') {
    const pending = this.#pending;
    if (!pending) return;
    clearTimeout(pending.timer);
    this.#pending = null;
    this.sinks.control({ type: 'resolved', id: pending.id, decision });
    this.#emitEvent(pending.line, pending.class, pending.unknown, decision, pending.rule);
    if (decision === 'confirmed') {
      this.classifier.commit({ menu: pending.menu });
      this.sinks.toDevice('\r');
    } else {
      this.sinks.toDevice(this.classifier.rules.cancelLine);
    }
    const queued = this.#queue;
    this.#queue = '';
    if (queued) this.input(queued);
  }

  #emitEvent(
    line: string,
    commandClass: CommandClass,
    unknown: boolean,
    verdict: CommandEvent['verdict'],
    rule: string | null,
  ) {
    this.sinks.event({
      type: 'command',
      line,
      class: commandClass,
      unknown,
      verdict,
      level: this.level,
      rule,
    });
    this.sinks.marker(
      `${verdict} ${commandClass}${unknown ? ' unknown' : ''}: ${line}`.slice(0, 300),
    );
  }

  close() {
    if (this.#pending) clearTimeout(this.#pending.timer);
    this.#pending = null;
  }
}

/** Length-delimited escape sequence starting at `start`, or null when it is incomplete. */
export function readEscape(data: string, start: number): string | null {
  const next = data[start + 1];
  if (next === undefined) return null;
  if (next === '[' || next === 'O') {
    let j = start + 2;
    while (j < data.length && j - start < 32) {
      const code = data.charCodeAt(j);
      if (next === 'O' || (code >= 0x40 && code <= 0x7e)) return data.slice(start, j + 1);
      j++;
    }
    return j - start >= 32 ? data.slice(start, j) : null;
  }
  return data.slice(start, start + 2);
}
