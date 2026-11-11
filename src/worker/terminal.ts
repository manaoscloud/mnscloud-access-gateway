// Device output hygiene before redaction: drops the escape sequences a hostile device could use
// against the operator's terminal or browser (OSC titles/hyperlinks/clipboard writes, DCS, APC,
// PM, SOS, and their 8-bit C1 forms). CSI (cursor, colors) and plain text pass through.

const MAX_SEQUENCE = 4096;

export class TerminalSanitizer {
  #state: 'text' | 'esc' | 'string' | 'string_esc' = 'text';
  #dropped = 0;

  push(chunk: string): string {
    let out = '';
    for (const ch of chunk) {
      const code = ch.codePointAt(0)!;
      switch (this.#state) {
        case 'text':
          if (ch === '\x1b') this.#state = 'esc';
          else if (
            code === 0x90 || code === 0x9d || code === 0x9e || code === 0x9f || code === 0x98
          ) {
            this.#enterString();
          } else out += ch;
          break;
        case 'esc':
          if (ch === ']' || ch === 'P' || ch === '_' || ch === '^' || ch === 'X') {
            this.#enterString();
          } else {
            out += '\x1b' + ch;
            this.#state = 'text';
          }
          break;
        case 'string':
          if (ch === '\x07' || code === 0x9c) this.#state = 'text';
          else if (ch === '\x1b') this.#state = 'string_esc';
          else if (++this.#dropped > MAX_SEQUENCE) this.#state = 'text';
          break;
        case 'string_esc':
          this.#state = ch === '\\' ? 'text' : 'string';
          break;
      }
    }
    return out;
  }

  #enterString() {
    this.#state = 'string';
    this.#dropped = 0;
  }
}

/** Token bucket for device output; `take` returns how long to pause reading (ms). */
export class OutputLimiter {
  #tokens: number;
  #last = Date.now();
  total = 0;

  constructor(private readonly bytesPerSecond: number, private readonly maxBytes: number) {
    this.#tokens = bytesPerSecond;
  }

  take(bytes: number, now = Date.now()): { pauseMs: number; exceeded: boolean } {
    this.total += bytes;
    this.#tokens = Math.min(
      this.bytesPerSecond,
      this.#tokens + ((now - this.#last) / 1000) * this.bytesPerSecond,
    );
    this.#last = now;
    this.#tokens -= bytes;
    const pauseMs = this.#tokens < 0 ? Math.ceil((-this.#tokens / this.bytesPerSecond) * 1000) : 0;
    return { pauseMs, exceeded: this.total > this.maxBytes };
  }
}
