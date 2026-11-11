import { TicketBook, ticketHash } from '../src/controller/ticket.ts';
import { assertEquals } from './assert.ts';

function ticket() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(
    /=+$/,
    '',
  );
}

Deno.test('ticket: only the SHA-256 is stored; single use', async () => {
  const book = new TicketBook<string>();
  const t = ticket();
  book.add(await ticketHash(t), Date.now() + 30000, 'conn-1');
  assertEquals((await book.consume(ticket())).ok, false);
  assertEquals(await book.consume(t), { ok: true, value: 'conn-1' });
  assertEquals(await book.consume(t), { ok: false, reason: 'used' });
});

Deno.test('ticket: malformed, expired and capped at 60 seconds', async () => {
  const book = new TicketBook<string>();
  assertEquals(await book.consume('short'), { ok: false, reason: 'malformed' });
  assertEquals(await book.consume(null), { ok: false, reason: 'malformed' });
  const now = Date.now();
  const late = ticket();
  // The API asked for 10 minutes: the gateway caps it at 60 s from receipt.
  book.add(await ticketHash(late), now + 600000, 'conn-2', now);
  assertEquals(await book.consume(late, now + 61000), { ok: false, reason: 'expired' });
  const swept = ticket();
  book.add(await ticketHash(swept), now + 1000, 'conn-3', now);
  assertEquals(book.sweep(now + 2000), ['conn-3']);
  assertEquals(book.size, 0);
});

Deno.test('ticket: hash is the hex SHA-256 of the ASCII ticket', async () => {
  assertEquals(
    await ticketHash('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});
