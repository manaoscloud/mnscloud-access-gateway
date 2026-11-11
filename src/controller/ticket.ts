// Browser tickets. The API generates 32 random bytes, gives the browser their base64url form and
// sends the gateway only the SHA-256 (hex) of that ASCII text inside the assignment. A ticket is
// valid once, for at most 60 seconds, and only for the connection of its assignment.

export const TICKET_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const TICKET_MAX_AGE_MS = 60_000;

export async function ticketHash(ticket: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ticket));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

interface Entry<T> {
  hash: string;
  expiresAt: number;
  value: T;
}

export type TicketResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: 'malformed' | 'unknown' | 'expired' | 'used' };

export class TicketBook<T> {
  #entries: Entry<T>[] = [];
  #used = new Map<string, number>();

  /** Registers an assignment; its ticket expires at min(expiresAt, receivedAt + 60 s). */
  add(hash: string, expiresAt: number, value: T, now = Date.now()) {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('Invalid ticket hash');
    this.#entries.push({ hash, expiresAt: Math.min(expiresAt, now + TICKET_MAX_AGE_MS), value });
  }

  /** Expired entries, removed from the book (their connections are finished as expired). */
  sweep(now = Date.now()): T[] {
    const expired = this.#entries.filter((entry) => entry.expiresAt <= now);
    this.#entries = this.#entries.filter((entry) => entry.expiresAt > now);
    for (const [hash, at] of this.#used) {
      if (at + TICKET_MAX_AGE_MS * 2 < now) this.#used.delete(hash);
    }
    return expired.map((entry) => entry.value);
  }

  remove(predicate: (value: T) => boolean) {
    this.#entries = this.#entries.filter((entry) => !predicate(entry.value));
  }

  get size() {
    return this.#entries.length;
  }

  async consume(ticket: string | null, now = Date.now()): Promise<TicketResult<T>> {
    if (!ticket || !TICKET_PATTERN.test(ticket)) return { ok: false, reason: 'malformed' };
    const hash = await ticketHash(ticket);
    if (this.#used.has(hash)) return { ok: false, reason: 'used' };
    const index = this.#entries.findIndex((entry) => constantTimeEqual(entry.hash, hash));
    if (index < 0) return { ok: false, reason: 'unknown' };
    const [entry] = this.#entries.splice(index, 1);
    this.#used.set(hash, now);
    if (entry.expiresAt <= now) return { ok: false, reason: 'expired' };
    return { ok: true, value: entry.value };
  }
}
