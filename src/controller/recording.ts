// Recording upload: asciicast v2 lines produced (already redacted) by the worker are cut into
// parts of about `partBytes` or `partSeconds` and uploaded in order with
// PUT /connections/:uuid/recording/parts/:n. The API stores them in Storage (90-day retention).

const encoder = new TextEncoder();

export type PartUploader = (index: number, bytes: Uint8Array, sha256: string) => Promise<void>;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export class RecordingUploader {
  #lines: string[] = [];
  #bytes = 0;
  #partStarted = Date.now();
  #index = 0;
  #total = 0;
  #chain: Promise<void> = Promise.resolve();
  #failed = false;
  #timer: ReturnType<typeof setInterval>;
  #hashes: string[] = [];

  constructor(
    private readonly upload: PartUploader,
    private readonly partBytes: number,
    private readonly partSeconds: number,
  ) {
    this.#timer = setInterval(() => {
      if (this.#bytes > 0 && Date.now() - this.#partStarted >= this.partSeconds * 1000) this.#cut();
    }, 1000);
  }

  add(line: string) {
    this.#lines.push(line);
    this.#bytes += encoder.encode(line).length;
    if (this.#bytes >= this.partBytes) this.#cut();
  }

  #cut() {
    if (!this.#lines.length) return;
    const bytes = encoder.encode(this.#lines.join(''));
    this.#lines = [];
    this.#bytes = 0;
    this.#partStarted = Date.now();
    const index = this.#index++;
    this.#total += bytes.length;
    this.#chain = this.#chain.then(async () => {
      const hash = await sha256Hex(bytes);
      this.#hashes.push(hash);
      if (this.#failed) return;
      try {
        await this.upload(index, bytes, hash);
      } catch {
        // A lost part is reported in finish (parts uploaded < parts produced).
        this.#failed = true;
      }
    });
  }

  /** Uploads the remainder; returns the summary sent in finish. */
  async finish(): Promise<
    { parts: number; bytes: number; sha256: string; complete: boolean } | null
  > {
    clearInterval(this.#timer);
    this.#cut();
    await this.#chain;
    if (this.#index === 0) return null;
    return {
      parts: this.#index,
      bytes: this.#total,
      sha256: await sha256Hex(encoder.encode(this.#hashes.join('\n'))),
      complete: !this.#failed,
    };
  }
}
