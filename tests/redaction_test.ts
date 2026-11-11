import { MASK, Redactor, stripAnsi } from '../src/worker/redaction.ts';
import { loadRules } from '../src/worker/rules.ts';
import type { ShellDialect } from '../src/shared/ipc.ts';
import { assert, assertEquals, assertNotIncludes } from './assert.ts';

const fixtures = JSON.parse(
  Deno.readTextFileSync(new URL('./fixtures/redaction.json', import.meta.url)),
) as Record<
  string,
  [string, string][]
>;

/** Feeds `text` in the given chunks with timed flushes between them, like the worker does. */
function feed(redactor: Redactor, chunks: string[], flushEvery = true) {
  let out = '';
  for (const chunk of chunks) {
    out += redactor.push(chunk);
    if (flushEvery) out += redactor.flush();
  }
  return out + redactor.flush(true) + redactor.end();
}

for (const dialect of Object.keys(fixtures) as ShellDialect[]) {
  Deno.test(`redaction fixtures: ${dialect} (every two-chunk split, flush between)`, () => {
    for (const [text, secret] of fixtures[dialect]) {
      for (let cut = 0; cut <= text.length; cut++) {
        const out = feed(new Redactor(loadRules(dialect).redact), [
          text.slice(0, cut),
          text.slice(cut),
        ]);
        assertNotIncludes(out, secret, `${dialect} cut ${cut}`);
        assert(out.includes(MASK), `${dialect} cut ${cut}: mask missing in ${JSON.stringify(out)}`);
      }
      const bytewise = feed(new Redactor(loadRules(dialect).redact), [...text]);
      assertNotIncludes(bytewise, secret, `${dialect} byte by byte`);
    }
  });
}

Deno.test('redaction: byte-by-byte echo of a typed password= value never leaks', () => {
  const text = '[admin@RB] > /user set admin password=Typed4Secret comment=x\r\n';
  const out = feed(new Redactor(loadRules('routeros').redact), [...text]);
  assertNotIncludes(out, 'Typed4Secret');
  assertNotIncludes(out, 'Typed4');
});

Deno.test('redaction: session secret literal split across chunks with timed flushes', () => {
  const redactor = new Redactor(loadRules('linux').redact);
  redactor.addSecret('pa55-word-of-session');
  const text = 'echoed: pa55-word-of-session and more\r\nprompt$ ';
  for (let cut = 1; cut < text.length; cut++) {
    const r = new Redactor(loadRules('linux').redact);
    r.addSecret('pa55-word-of-session');
    const out = feed(r, [text.slice(0, cut), text.slice(cut)]);
    assertNotIncludes(out, 'pa55-word-of-session', `cut ${cut}`);
    for (const fragment of ['pa55-wo', 'word-of-se', 'of-session']) {
      assertNotIncludes(out, fragment, `cut ${cut}`);
    }
  }
  // A prompt without newline is still shown after the timed flush.
  assertEquals(redactor.push('user@host:~$ '), '');
  assertEquals(redactor.flush(), 'user@host:~$ ');
});

Deno.test('redaction: private key block across many chunks is fully masked', () => {
  const key =
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nline2secretmaterial\n-----END RSA PRIVATE KEY-----\nafter\n';
  for (let size = 1; size <= 9; size++) {
    const chunks: string[] = [];
    for (let i = 0; i < key.length; i += size) chunks.push(key.slice(i, i + size));
    const out = feed(new Redactor(loadRules('linux').redact), chunks);
    assertNotIncludes(out, 'MIIEowIBAAKCAQEAx', `size ${size}`);
    assertNotIncludes(out, 'line2secret', `size ${size}`);
    assert(out.includes('after'), `size ${size}: text after the block is kept`);
  }
});

Deno.test('redaction: forced flush of a very long value keeps masking the continuation', () => {
  const redactor = new Redactor(loadRules('linux').redact);
  const long = 'x'.repeat(5000);
  let out = redactor.push('token=' + long.slice(0, 4500));
  out += redactor.push(long.slice(4500) + ' end\n');
  assertNotIncludes(out, 'xxxx');
  assert(out.includes(' end'), out.slice(-20));
});

Deno.test('redaction: ANSI map keeps escape codes outside the masked value', () => {
  const s = stripAnsi('a\x1b[31mb\x1b[0mc');
  assertEquals(s.text, 'abc');
  assertEquals(s.map, [0, 6, 11, 12]);
});

Deno.test('redaction: command event lines are masked too', () => {
  const r = new Redactor(loadRules('routeros').redact);
  assertEquals(r.redactText('/user set admin password=abc123'), `/user set admin password=${MASK}`);
});
