import { parseAssignment } from '../src/controller/contract.ts';
import { Session } from '../src/controller/session.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import {
  connectApiSsl,
  decodeLength,
  encodeLength,
  encodeSentence,
  RouterOsApi,
  SentenceReader,
  tlsPin,
} from '../src/worker/routeros_api.ts';
import { validateInit } from '../src/worker/worker.ts';
import { assert, assertEquals, assertRejects, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import { makeCertificate, startRouterOs } from './routeros_mock.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

Deno.test('routeros api: length encoding round trip at every boundary', () => {
  for (const n of [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x200000, 0xfffffff, 0x10000000]) {
    const encoded = encodeLength(n);
    assertEquals(decodeLength(encoded), [n, encoded.length], String(n));
  }
  const reader = new SentenceReader();
  const bytes = encodeSentence(['!re', '=name=' + 'x'.repeat(300), '=b=2']);
  const out: string[][] = [];
  for (const b of bytes) out.push(...reader.push(Uint8Array.of(b))); // byte by byte
  assertEquals(out, [['!re', '=name=' + 'x'.repeat(300), '=b=2']]);
  assertThrows(() => new SentenceReader().push(Uint8Array.of(0xf8)), /Invalid/);
});

Deno.test('routeros api: TLS pin is SHA256:<base64> like the SSH host key pin', () => {
  assertEquals(tlsPin('00'.repeat(31) + 'FF').length, 'SHA256:'.length + 43);
});

Deno.test({
  name: 'routeros api: login, identity and resource over API-SSL; wrong password is auth_failed',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const certificate = await makeCertificate();
    const mock = await startRouterOs(certificate, 'ros-pass-1');
    const connection = await connectApiSsl('127.0.0.1', mock.port, 5000);
    assert(/^SHA256:[A-Za-z0-9+/]{43}$/.test(connection.pin));
    const api = new RouterOsApi(connection.transport);
    await api.login('support', 'ros-pass-1');
    const facts = await api.facts();
    assertEquals([facts.identity, facts.version, facts.boardName], [
      'RB-Lab',
      '7.24.6 (stable)',
      'CHR',
    ]);
    api.close();
    const bad = new RouterOsApi((await connectApiSsl('127.0.0.1', mock.port, 5000)).transport);
    await assertRejects(() => bad.login('support', 'wrong'), /refused the credential/);
    bad.close();
    await mock.close();
  },
});

Deno.test('routeros api: plain API 8728, Telnet and console over the API are refused by the worker', () => {
  const init = {
    t: 'init',
    connectionUUID: ASSIGNMENT.connectionUUID,
    mode: 'test',
    protocol: 'routeros_api',
    target: { address: '192.0.2.1', port: 8728 },
    shellDialect: 'routeros',
    username: 'u',
    level: 'n1',
    hostKey: { pinned: null },
    tls: { pinned: null },
    terminal: { cols: 80, rows: 24 },
    limits: {},
    recording: false,
  };
  assertThrows(() => validateInit(init), /protocol_refused/);
  assertThrows(
    () => validateInit({ ...init, target: { address: '192.0.2.1', port: 23 }, protocol: 'ssh' }),
    /protocol_refused/,
  );
  assertThrows(
    () => validateInit({ ...init, mode: 'console', target: { address: '192.0.2.1', port: 8729 } }),
    /protocol_refused/,
  );
  assertThrows(
    () =>
      validateInit({ ...init, protocol: 'telnet', target: { address: '192.0.2.1', port: 8729 } }),
    /invalid_assignment/,
  );
});

Deno.test({
  name: 'routeros api: "Testar acesso" through a worker pins the certificate, then reports facts',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const certificate = await makeCertificate();
    const mock = await startRouterOs(certificate, 'ros-pass-2');
    for (const pin of ['accept', 'block'] as const) {
      let finished: FinishBody | null = null;
      const calls: string[] = [];
      const session = new Session(
        parseAssignment({
          ...ASSIGNMENT,
          connectionUUID: crypto.randomUUID(),
          mode: 'test',
          protocol: 'routeros_api',
          ticket: null,
          username: 'support',
          target: { address: '127.0.0.1', port: mock.port },
        }),
        {
          api: {
            hostKey: (_c, body) => {
              calls.push(`hostkey:${body.kind}:${body.result}`);
              return Promise.resolve({ decision: pin, pinned: pin === 'accept' });
            },
            credential: () => {
              calls.push('credential');
              return Promise.resolve({
                credentialUseUUID: crypto.randomUUID(),
                wrapToken: 'wrap-token-0123456789',
                ttlSeconds: 30,
              });
            },
            credentialResult: (_c, body) => {
              calls.push(`result:${body.result}`);
              return Promise.resolve();
            },
            events: () => Promise.resolve(),
            recordingPart: () => Promise.resolve(),
            finish: (_c, body) => {
              finished = body;
              return Promise.resolve();
            },
          },
          unwrap: () => Promise.resolve({ password: 'ros-pass-2' }),
          launcher: new DirectLauncher(ROOT),
          networks: null,
          sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
          log: () => {},
        },
      );
      session.start();
      await session.done;
      const body = finished as FinishBody | null;
      if (pin === 'accept') {
        assertEquals(calls, ['hostkey:tls:unpinned', 'credential', 'result:used']);
        assertEquals([body?.state, body?.reason, body?.facts?.identity], [
          'closed',
          'test_ok',
          'RB-Lab',
        ]);
      } else {
        assertEquals(calls, ['hostkey:tls:unpinned']);
        assertEquals(body?.reason, 'hostkey_rejected');
      }
    }
    assert(
      !mock.sentences.some((s) => s.some((w) => w.includes('ros-pass-2') && s[0] !== '/login')),
    );
    await mock.close();
  },
});
