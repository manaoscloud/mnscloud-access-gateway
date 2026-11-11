// asciicast v2 writer (https://docs.asciinema.org/manual/asciicast/v2/). Only redacted output,
// resizes and markers are recorded; keystrokes are never recorded (they can carry passwords typed
// at device prompts).

export interface CastHeader {
  width: number;
  height: number;
  timestamp: number;
  title?: string;
}

export class AsciicastWriter {
  readonly #start: number;
  constructor(private readonly header: CastHeader, startMs = header.timestamp * 1000) {
    this.#start = startMs;
  }

  #time(nowMs: number) {
    return Math.max(0, Math.round(nowMs - this.#start) / 1000);
  }

  headerLine(): string {
    return JSON.stringify({
      version: 2,
      width: this.header.width,
      height: this.header.height,
      timestamp: this.header.timestamp,
      env: { TERM: 'xterm-256color' },
      ...(this.header.title ? { title: this.header.title } : {}),
    }) + '\n';
  }

  output(data: string, nowMs = Date.now()): string {
    return JSON.stringify([this.#time(nowMs), 'o', data]) + '\n';
  }

  marker(label: string, nowMs = Date.now()): string {
    return JSON.stringify([this.#time(nowMs), 'm', label]) + '\n';
  }

  resize(cols: number, rows: number, nowMs = Date.now()): string {
    return JSON.stringify([this.#time(nowMs), 'r', `${cols}x${rows}`]) + '\n';
  }
}
