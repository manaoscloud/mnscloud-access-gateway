// The installer's listener certificate must be accepted by a pinned rustls client (health.ts and
// the edge): a CA certificate presented by the server fails with CaUsedAsEndEntity.

import { assert, assertEquals } from './assert.ts';

const COMMON = new URL('../scripts/lib/common.sh', import.meta.url).pathname;

async function bash(script: string): Promise<{ ok: boolean; out: string }> {
  const result = await new Deno.Command('bash', {
    args: ['-c', script, 'test', COMMON],
    stdout: 'piped',
    stderr: 'null',
  }).output();
  return { ok: result.success, out: new TextDecoder().decode(result.stdout).trim() };
}

Deno.test('installer listener certificate is a pinnable TLS server certificate', async () => {
  // The directory is created and removed by bash: the test itself writes nothing.
  const made = await bash(
    'source "$1"; d="$(mktemp -d)"; write_listener_certificate "$d" 127.0.0.1; printf %s "$d"',
  );
  assert(made.ok && made.out.length > 0, 'write_listener_certificate failed');
  const dir = made.out;
  try {
    const cert = Deno.readTextFileSync(`${dir}/cert.pem`);
    const key = Deno.readTextFileSync(`${dir}/key.pem`);
    const server = Deno.serve(
      { hostname: '127.0.0.1', port: 0, cert, key, onListen: () => {} },
      () => Response.json({ status: 'ok' }),
    );
    try {
      const client = Deno.createHttpClient({ caCerts: [cert] });
      const response = await fetch(`https://127.0.0.1:${server.addr.port}/healthz`, { client });
      assertEquals((await response.json()).status, 'ok');
      client.close();
    } finally {
      await server.shutdown();
    }
    const fresh = await bash(
      `source "$1"; listener_certificate_stale '${dir}' && echo stale || echo fresh`,
    );
    assertEquals(fresh.out, 'fresh');
  } finally {
    await bash(`rm -rf '${dir}'`);
  }
});

Deno.test('a CA listener certificate from an earlier installer is rewritten', async () => {
  const made = await bash(
    'd="$(mktemp -d)"; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes ' +
      '-days 365 -subj /CN=old -addext basicConstraints=critical,CA:TRUE -keyout "$d/key.pem" ' +
      '-out "$d/cert.pem" >/dev/null 2>&1; printf %s "$d"',
  );
  assert(made.ok && made.out.length > 0, 'openssl failed');
  try {
    const stale = await bash(`source "$1"; listener_certificate_stale '${made.out}' && echo stale`);
    assertEquals(stale.out, 'stale');
    const missing = await bash(
      `source "$1"; listener_certificate_stale '${made.out}/none' && echo stale`,
    );
    assertEquals(missing.out, 'stale');
  } finally {
    await bash(`rm -rf '${made.out}'`);
  }
});
