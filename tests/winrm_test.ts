// Native WinRM (HTTPS, WS-Man/WinRS) for the Windows dialect: strict parsing units and the full
// worker lifecycle (Session -> real worker process -> synthetic HTTPS/WS-Man endpoint). The
// endpoint is a protocol simulator: it does not prove behaviour of a real Windows host.

import { X509Certificate } from 'node:crypto';
import net from 'node:net';
import { parseAssignment } from '../src/controller/contract.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { Session } from '../src/controller/session.ts';
import type { RuntimeEvent, SessionApi } from '../src/controller/session.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import { type ExecPayload, type ExecResult, execSha256 } from '../src/shared/exec.ts';
import { parseServerFrame } from '../src/shared/framing.ts';
import { tlsPin } from '../src/worker/routeros_api.ts';
import type { ApiTransport } from '../src/worker/routeros_api.ts';
import {
  basicAuthorization,
  decodeBase64,
  hostAuthority,
  HttpConnection,
  parseXml,
  runWinrmCommand,
  WinrmError,
  WsmanClient,
  XML_LIMITS,
} from '../src/worker/winrm.ts';
import { assert, assertEquals, assertNotIncludes, assertRejects, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import { makeCertificate, type MockCertificate } from './routeros_mock.ts';
import { startWinrm, type WinrmMock, type WinrmMockOptions } from './winrm_mock.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const PASSWORD = 'W1nRM-Pa55word!';

// ---------------------------------------------------------------------------------------------
// Units: XML

Deno.test('winrm xml: bounded, no DTD/entities/CDATA/comments, predefined references only', () => {
  const doc = parseXml(
    '<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="urn:x" xmlns:rsp="urn:rsp"><s:Body a="1 &amp; 2">' +
      '<rsp:Text>a &lt; b &#65;&#x42;</rsp:Text><empty/></s:Body></s:Envelope>',
  );
  assertEquals(doc.name, 'Envelope');
  assertEquals(doc.children[0].attrs, { a: '1 & 2' });
  assertEquals(doc.children[0].children[0].text, 'a < b AB');
  const bad: string[] = [
    '<!DOCTYPE a [<!ENTITY x "y">]><a/>',
    '<?xml version="1.0"?><!DOCTYPE a><a/>',
    '<a><![CDATA[x]]></a>',
    '<a><!-- c --></a>',
    '<a><?pi x?></a>',
    '<a>&xxe;</a>',
    '<a>&#0;</a>',
    '<a b="&xxe;"/>',
    '<a></b>',
    '<a><b></a></b>',
    '<a/><b/>',
    'text<a/>',
    '<a/>tail',
    '<a',
    '<a b=c/>',
    '<1a/>',
    '<a>',
    '',
  ];
  for (const text of bad) {
    assertThrows(() => parseXml(text), /./);
  }
  // Depth, node count and size are bounded.
  assertThrows(
    () => parseXml('<a>'.repeat(XML_LIMITS.depth + 1) + '</a>'.repeat(XML_LIMITS.depth + 1)),
    /Too deep/,
  );
  assertThrows(() => parseXml('<a>' + '<b/>'.repeat(XML_LIMITS.nodes + 1) + '</a>'), /Too many/);
  assertThrows(() => parseXml('<a>' + 'x'.repeat(XML_LIMITS.bytes) + '</a>'), /too large/);
});

Deno.test('winrm units: base64, Basic header and host authority', () => {
  assertEquals(new TextDecoder().decode(decodeBase64('aGVsbG8=')), 'hello');
  assertEquals(new TextDecoder().decode(decodeBase64('aGVs\r\nbG8=')), 'hello');
  for (const bad of ['aGVsbG8', '@@@@', 'a=bc', '====', 'AB==', 'AAB=']) {
    assertThrows(() => decodeBase64(bad), /base64/);
  }
  assertEquals(basicAuthorization('support', 'p:w'), 'Basic c3VwcG9ydDpwOnc=');
  assertEquals(hostAuthority('203.0.113.10', 5986), '203.0.113.10:5986');
  assertEquals(hostAuthority('2001:db8::1', 5986), '[2001:db8::1]:5986');
});

// ---------------------------------------------------------------------------------------------
// Units: HTTP framing over a scripted transport

function scripted(replies: (Uint8Array | string)[][]) {
  let onData: (c: Uint8Array) => void = () => {};
  let onClose: (e?: Error) => void = () => {};
  const written: string[] = [];
  let closed = false;
  const transport: ApiTransport = {
    write: (bytes) => {
      written.push(new TextDecoder().decode(bytes));
      const next = replies.shift();
      queueMicrotask(() => {
        for (const part of next ?? []) {
          onData(typeof part === 'string' ? new TextEncoder().encode(part) : part);
        }
      });
    },
    onData: (h) => (onData = h),
    onClose: (h) => (onClose = h),
    close: () => {
      closed = true;
      queueMicrotask(() => onClose());
    },
  };
  return { transport, written, closed: () => closed };
}

const http = (status: string, headers: string[], body = '') =>
  `HTTP/1.1 ${status}\r\n${headers.join('\r\n')}${headers.length ? '\r\n' : ''}\r\n${body}`;
const SOAP = 'Content-Type: application/soap+xml;charset=UTF-8';

Deno.test('winrm http: Content-Length and chunked bodies, one request at a time, fixed target', async () => {
  const body = '<a/>';
  const { transport, written } = scripted([
    [http('200 OK', [SOAP, `Content-Length: ${body.length}`], body)],
    // chunked, split across arbitrary reads
    [
      'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n<a',
      '\r\n2\r\n/>\r',
      '\n0\r\n\r\n',
    ],
  ]);
  const conn = new HttpConnection(transport, '203.0.113.10:5986', 'Basic x');
  assertEquals((await conn.request('one', 1000)).body, '<a/>');
  assertEquals((await conn.request('two', 1000)).body, '<a/>');
  assert(written[0].startsWith('POST /wsman HTTP/1.1\r\nHost: 203.0.113.10:5986\r\n'));
  assert(written[0].includes('Authorization: Basic x\r\n'));
  assert(written[0].includes('Content-Length: 3\r\n'));
  // A second request while one is in flight is refused.
  const slow = scripted([[]]);
  const waiting = new HttpConnection(slow.transport, 'h:1', 'Basic x');
  const first = waiting.request('x', 200);
  await assertRejects(() => waiting.request('y', 200), /in progress/);
  await assertRejects(() => first, /in time/);
});

Deno.test('winrm http: redirects, 401, non-SOAP, framing violations and oversize end the connection', async () => {
  const cases: [string, (string | Uint8Array)[], RegExp][] = [
    ['401', [http('401 Unauthorized', ['Content-Length: 0'])], /refused the credential/],
    ['redirect', [
      http('307 Temporary Redirect', ['Location: https://evil.example/', 'Content-Length: 0']),
    ], /redirect/],
    [
      'not soap',
      [http('200 OK', ['Content-Type: text/html', 'Content-Length: 1'], 'x')],
      /Not a SOAP/,
    ],
    [
      '500 html',
      [http('500 Err', ['Content-Type: text/html', 'Content-Length: 1'], 'x')],
      /Not a SOAP/,
    ],
    ['503', [http('503 Busy', ['Content-Length: 0'])], /HTTP 503/],
    ['not http', ['SSH-2.0-OpenSSH\r\n\r\n'], /Not an HTTP/],
    ['http/1.0', ['HTTP/1.0 200 OK\r\n\r\n'], /Not an HTTP/],
    ['no length', [http('200 OK', [SOAP])], /without a length/],
    [
      'dup length',
      [http('200 OK', [SOAP, 'Content-Length: 1', 'Content-Length: 1'], 'x')],
      /Duplicate/,
    ],
    [
      'both',
      [http('200 OK', [SOAP, 'Content-Length: 1', 'Transfer-Encoding: chunked'], 'x')],
      /Unsupported/,
    ],
    ['bad length', [http('200 OK', [SOAP, 'Content-Length: -1'])], /Invalid Content-Length/],
    ['huge length', [http('200 OK', [SOAP, 'Content-Length: 99999999'])], /Oversized/],
    ['big header', ['HTTP/1.1 200 OK\r\nX: ' + 'a'.repeat(20000)], /Oversized HTTP header/],
    ['extra bytes', [http('200 OK', [SOAP, 'Content-Length: 1'], 'xyz')], /extra data/],
    ['bad chunk', [
      'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n',
    ], /chunk size/],
    ['trailer', [
      'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n',
    ], /trailer/],
  ];
  for (const [name, reply, pattern] of cases) {
    const { transport } = scripted([reply]);
    const conn = new HttpConnection(transport, 'h:1', 'Basic x');
    await assertRejects(() => conn.request('x', 500), pattern);
    // After any of these the connection is not reused.
    await assertRejects(() => conn.request('x', 500));
    assert(name.length > 0);
  }
  // A server that closes the connection is not reused either.
  const { transport } = scripted([
    [http('200 OK', [SOAP, 'Content-Length: 0', 'Connection: close'])],
  ]);
  const conn = new HttpConnection(transport, 'h:1', 'Basic x');
  await conn.request('x', 500);
  assertEquals(conn.usable, false);
  await assertRejects(() => conn.request('x', 500), /closed/);
  // Data nobody asked for is a protocol error.
  const rogue = scripted([]);
  const c2 = new HttpConnection(rogue.transport, 'h:1', 'Basic x');
  rogue.transport.close();
  await assertRejects(() => c2.request('x', 500), /Closed|closed/);
  assert(WinrmError.name === 'WinrmError');
});

// ---------------------------------------------------------------------------------------------
// Integration harness

class FakeApi implements SessionApi {
  calls: string[] = [];
  results: ExecResult[] = [];
  received: RuntimeEvent[] = [];
  parts: Uint8Array[] = [];
  finished: FinishBody | null = null;
  constructor(private readonly pin: 'accept' | 'block' = 'accept') {}
  hostKey(_c: string, body: { kind: string; result: string }) {
    this.calls.push(`hostkey:${body.kind}:${body.result}`);
    return Promise.resolve({
      decision: body.result === 'mismatch' ? 'block' as const : this.pin,
      pinned: this.pin === 'accept',
    });
  }
  credential() {
    this.calls.push('credential');
    return Promise.resolve({
      credentialUseUUID: '11111111-2222-4333-8444-555555555555',
      wrapToken: 'wrap-token-0123456789',
      ttlSeconds: 30,
    });
  }
  credentialResult(_c: string, body: { result: string }) {
    this.calls.push(`result:${body.result}`);
    return Promise.resolve();
  }
  events(_c: string, events: RuntimeEvent[]) {
    this.received.push(...events);
    return Promise.resolve();
  }
  recordingPart(_c: string, _i: number, bytes: Uint8Array) {
    this.parts.push(bytes);
    return Promise.resolve();
  }
  attach() {
    return Promise.resolve({ role: 'operator' as const });
  }
  detach() {
    return Promise.resolve();
  }
  execResult(_c: string, result: ExecResult) {
    this.results.push(result);
    return Promise.resolve();
  }
  finish(_c: string, body: FinishBody) {
    this.calls.push(`finish:${body.reason}`);
    this.finished = body;
    return Promise.resolve();
  }
}

type Pin = 'match' | 'mismatch' | null;

interface Harness {
  certificate: MockCertificate;
  mock: WinrmMock;
  pinOf(kind: Pin): string | null;
}

async function withMock<T>(
  options: Partial<WinrmMockOptions>,
  fn: (h: Harness) => Promise<T>,
): Promise<T> {
  const certificate = await makeCertificate();
  const mock = await startWinrm(certificate, { password: PASSWORD, ...options });
  const real = tlsPin(new X509Certificate(certificate.cert).fingerprint256);
  try {
    return await fn({
      certificate,
      mock,
      pinOf: (kind) =>
        kind === 'match' ? real : kind === 'mismatch' ? 'SHA256:' + 'A'.repeat(43) : null,
    });
  } finally {
    await mock.close();
  }
}

function payloadOf(connectionUUID: string, steps: string[]): ExecPayload {
  const base: ExecPayload = {
    kind: 'read',
    requestUUID: connectionUUID.replaceAll('-', '').toUpperCase(),
    steps,
    verify: [],
    rollback: [],
    safeChange: 'none',
    rollbackSeconds: 300,
    backupName: null,
    changeLog: null,
    sha256: '',
  };
  return { ...base, sha256: execSha256(base) };
}

function build(
  mode: 'test' | 'exec' | 'console',
  port: number,
  h: Harness,
  options: {
    pin?: Pin;
    steps?: string[];
    level?: 'n1' | 'n2' | 'n3';
    password?: string;
    unwrap?: () => Promise<{ username: string; password: string }>;
    apiPin?: 'accept' | 'block';
    limits?: Record<string, number>;
  } = {},
) {
  const connectionUUID = crypto.randomUUID();
  const api = new FakeApi(options.apiPin);
  const assignment = parseAssignment({
    ...ASSIGNMENT,
    connectionUUID,
    mode,
    protocol: 'winrm',
    shellDialect: 'windows',
    target: { address: '127.0.0.1', port },
    username: 'support',
    level: options.level ?? 'n2',
    ticket: mode === 'console' ? ASSIGNMENT.ticket : null,
    tls: { pinned: h.pinOf(options.pin ?? null) },
    hostKey: { pinned: null },
    limits: { ...ASSIGNMENT.limits, ...(options.limits ?? {}) },
    recording: { enabled: mode === 'console', partBytes: 65536, partSeconds: 5 },
    ...(mode === 'exec' ? { exec: payloadOf(connectionUUID, options.steps ?? ['ver']) } : {}),
  });
  const session = new Session(assignment, {
    api,
    unwrap: options.unwrap ??
      (() => Promise.resolve({ username: 'support', password: options.password ?? PASSWORD })),
    launcher: new DirectLauncher(ROOT),
    networks: null,
    sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
    log: () => {},
    execResultRetryMs: [20, 20],
  });
  return { session, api };
}

async function runMode(
  mode: 'test' | 'exec',
  h: Harness,
  options: Parameters<typeof build>[3] = {},
) {
  const { session, api } = build(mode, h.mock.port, h, options);
  session.start();
  await session.done;
  return { api, result: api.results[0], reason: api.finished?.reason, state: api.finished?.state };
}

const sanitize = { sanitizeOps: false, sanitizeResources: false };

// ---------------------------------------------------------------------------------------------
// Access test: login AND a created shell

Deno.test({
  name: 'winrm test: pin decision on raw TLS, Basic login, Create+Delete of a WinRS shell, facts',
  ...sanitize,
  fn: () =>
    withMock({}, async (h) => {
      const r = await runMode('test', h, { pin: 'match' });
      assertEquals([r.state, r.reason], ['closed', 'test_ok']);
      assertEquals(r.api.calls, [
        'hostkey:tls:match',
        'credential',
        'result:used',
        'finish:test_ok',
      ]);
      assertEquals(h.mock.requests.map((q) => q.action), ['create', 'delete']);
      assert(h.mock.requests.every((q) => q.path === '/wsman'));
      assert(
        h.mock.requests.every((q) => q.authorization === basicAuthorization('support', PASSWORD)),
      );
      assert(h.mock.requests.every((q) => q.contentType?.startsWith('application/soap+xml')));
      assertEquals(h.mock.openShells.size, 0);
      assertEquals(h.mock.connections, 1);
      // Create asks for the cmd shell with stdin/stdout/stderr and UTF-8; never PowerShell.
      assert(h.mock.requests[0].body.includes('windows/shell/cmd'));
      assert(!/powershell|PSRP|CredSSP/i.test(h.mock.requests[0].body));
      assertNotIncludes(JSON.stringify(r.api.received) + JSON.stringify(r.api.finished), PASSWORD);
    }),
});

Deno.test({
  name: 'winrm test: an unpinned certificate is decided before the credential is pulled',
  ...sanitize,
  fn: () =>
    withMock({}, async (h) => {
      const accepted = await runMode('test', h, { pin: null });
      assertEquals(accepted.api.calls.slice(0, 2), ['hostkey:tls:unpinned', 'credential']);
      assertEquals(accepted.reason, 'test_ok');
      const before = h.mock.requests.length;
      const blocked = await runMode('test', h, { pin: null, apiPin: 'block' });
      assertEquals(blocked.reason, 'hostkey_rejected');
      assertEquals(blocked.state, 'refused');
      assert(!blocked.api.calls.includes('credential'));
      assertEquals(h.mock.requests.length, before, 'no HTTP request was sent');
    }),
});

Deno.test({
  name: 'winrm test: a TLS pin mismatch ends before any credential or HTTP byte',
  ...sanitize,
  fn: () =>
    withMock({}, async (h) => {
      const r = await runMode('test', h, { pin: 'mismatch' });
      assertEquals([r.state, r.reason], ['refused', 'hostkey_mismatch']);
      assertEquals(r.api.calls, ['hostkey:tls:mismatch', 'finish:hostkey_mismatch']);
      assertEquals(h.mock.requests.length, 0);
      // Same for exec: nothing runs, nothing is sent.
      const e = await runMode('exec', h, { pin: 'mismatch', steps: ['ver'] });
      assertEquals(e.reason, 'hostkey_mismatch');
      assert(!e.api.calls.includes('credential'));
      assertEquals(h.mock.requests.length, 0);
    }),
});

Deno.test({
  name:
    'winrm test: wrong password, WinRS fault, redirect and hostile replies are explicit failures',
  ...sanitize,
  fn: async () => {
    await withMock({}, async (h) => {
      const r = await runMode('test', h, { pin: 'match', password: 'wrong' });
      assertEquals([r.state, r.reason], ['failed', 'auth_failed']);
      assert(r.api.calls.includes('result:auth_failed'));
      assertEquals(h.mock.requests.map((q) => q.action), ['create']);
    });
    await withMock({ denyAll: true }, async (h) => {
      assertEquals((await runMode('test', h, { pin: 'match' })).reason, 'auth_failed');
    });
    const kinds: Record<string, string> = {
      fault: 'protocol_error',
      redirect: 'protocol_error',
      html: 'protocol_error',
      'bad-shell-id': 'protocol_error',
      dtd: 'protocol_error',
      'big-header': 'protocol_error',
      'wrong-relates': 'protocol_error',
    };
    for (const [failCreate, reason] of Object.entries(kinds)) {
      await withMock({ failCreate: failCreate as never }, async (h) => {
        const r = await runMode('test', h, { pin: 'match' });
        assertEquals([r.state, r.reason], ['failed', reason], failCreate);
        // The login may have worked but readiness did not: never reported as used or as a bad password.
        assert(!r.api.calls.includes('result:used'), failCreate);
        assert(!r.api.calls.includes('result:auth_failed'), failCreate);
        // A redirect is never followed: exactly one request reached the endpoint.
        if (failCreate === 'redirect') assertEquals(h.mock.requests.length, 1);
        assertEquals(h.mock.connections, 1, failCreate);
      });
    }
  },
});

Deno.test({
  name: 'winrm test: a plain (non-TLS) listener fails as tls_failed before any credential',
  ...sanitize,
  fn: async () => {
    const server = net.createServer((socket) => {
      socket.on('error', () => {});
      socket.end('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as net.AddressInfo).port;
    try {
      const h = {
        certificate: await makeCertificate(),
        mock: undefined as never,
        pinOf: () => null,
      };
      const { session, api } = build('test', port, h, {});
      session.start();
      await session.done;
      assertEquals(api.finished?.reason, 'tls_failed');
      assert(!api.calls.includes('credential'));
    } finally {
      server.close();
    }
  },
});

// ---------------------------------------------------------------------------------------------
// Exec (AI copilot)

Deno.test({
  name: 'winrm exec: exact reads over Command/Receive/Delete, base64 stdout and stderr, redaction',
  ...sanitize,
  fn: () =>
    withMock({
      commands: {
        ver: { stdout: '\r\nMicrosoft Windows [Version 10.0.20348.2113]\r\n' },
        hostname: { stdout: 'SRV-ÁÇÃO\r\n', stderr: `warn password=${PASSWORD}\r\n` },
        systeminfo: { stdout: `Host Name: SRV\r\nNote: token ${PASSWORD}\r\n`, slowReceives: 2 },
      },
    }, async (h) => {
      const r = await runMode('exec', h, {
        pin: 'match',
        steps: ['ver', 'hostname', 'systeminfo'],
      });
      assertEquals(r.result.status, 'ok');
      assertEquals(r.result.error, null);
      assertEquals(r.result.steps.map((s) => [s.command, s.exitCode, s.class, s.verdict]), [
        ['ver', 0, 'read', 'allowed'],
        ['hostname', 0, 'read', 'allowed'],
        ['systeminfo', 0, 'read', 'allowed'],
      ]);
      assert(r.result.steps[0].output.includes('Windows [Version 10.0.20348.2113]'));
      assert(r.result.steps[1].output.includes('SRV-ÁÇÃO'));
      assertNotIncludes(JSON.stringify(r.result), PASSWORD);
      assertEquals(h.mock.commands, ['ver', 'hostname', 'systeminfo']);
      // Lifecycle: one shell, deleted at the end; the credential never leaves the worker.
      assertEquals(h.mock.deletes.length, 1);
      assertEquals(h.mock.openShells.size, 0);
      assertEquals(h.mock.connections, 1);
      assertEquals(r.reason, 'exec_done');
      assertEquals(r.api.calls.filter((c) => c === 'credential').length, 1);
      assertNotIncludes(JSON.stringify(r.api.received) + JSON.stringify(r.api.finished), PASSWORD);
    }),
});

Deno.test({
  name: 'winrm exec: chunked responses work; a server that closes the connection fails closed',
  ...sanitize,
  fn: async () => {
    await withMock({ chunked: true, commands: { hostname: { stdout: 'SRV\r\n' } } }, async (h) => {
      const r = await runMode('exec', h, { pin: 'match', steps: ['hostname'] });
      assertEquals(r.result.status, 'ok');
    });
    await withMock({ failCreate: 'no-keepalive' }, async (h) => {
      const r = await runMode('exec', h, { pin: 'match', steps: ['ver'] });
      assertEquals(r.result.status, 'failed');
      assertEquals(r.result.steps.length, 0);
    });
  },
});

Deno.test({
  name: 'winrm exec: anything but the exact reads blocks the request before any connection',
  ...sanitize,
  fn: () =>
    withMock({}, async (h) => {
      const lists = [
        ['ver', 'systeminfo & del c:\\x'],
        ['powershell -c Get-Process'],
        ['ipconfig'],
        ['ipconfig /all | findstr IPv4'],
        ['type c:\\windows\\system32\\config\\sam'],
        ['net user admin P@ss /add'],
        ['VER'],
        ['route print > c:\\x'],
        ['set'],
        ['cmd /c ver'],
      ];
      for (const steps of lists) {
        const r = await runMode('exec', h, { pin: 'match', steps, level: 'n3' });
        assertEquals(r.result.status, 'blocked', JSON.stringify(steps));
        assertEquals(r.result.error?.code, 'EXEC_BLOCKED');
        assert(!r.api.calls.includes('credential'));
      }
      assertEquals(h.mock.requests.length, 0);
    }),
});

Deno.test({
  name:
    'winrm exec: non-zero exit, faults, malformed and mismatched replies end the request and delete the shell',
  ...sanitize,
  fn: async () => {
    await withMock({ commands: { ver: { stdout: 'x', exit: 1 } } }, async (h) => {
      const r = await runMode('exec', h, { pin: 'match', steps: ['ver', 'hostname'] });
      assertEquals([r.result.status, r.result.error?.code], ['failed', 'COMMAND_FAILED']);
      assertEquals(h.mock.commands, ['ver']);
      assertEquals(h.mock.deletes.length, 1);
    });
    const kinds: Record<string, string> = {
      fault: 'WINRM_FAULT_unknown',
      dtd: 'WINRM_XML',
      'bad-base64': 'WINRM_PROTOCOL',
      'wrong-command-id': 'WINRM_PROTOCOL',
      'wrong-stream': 'WINRM_PROTOCOL',
    };
    for (const [failReceive, code] of Object.entries(kinds)) {
      await withMock({
        failReceive: failReceive as never,
        commands: { ver: { stdout: 'x' } },
      }, async (h) => {
        const r = await runMode('exec', h, { pin: 'match', steps: ['ver'] });
        assertEquals([r.result.status, r.result.error?.code], ['failed', code], failReceive);
        assertEquals(r.result.steps.length, 0, failReceive);
        assertNotIncludes(JSON.stringify(r.result), PASSWORD);
      });
    }
  },
});

Deno.test({
  name: 'winrm exec: output over the cap stops the command (Signal terminate) and fails',
  ...sanitize,
  fn: () =>
    withMock({
      commands: { systeminfo: { stdoutBytes: new Uint8Array(200 * 1024).fill(65) } },
    }, async (h) => {
      const r = await runMode('exec', h, { pin: 'match', steps: ['systeminfo', 'ver'] });
      assertEquals([r.result.status, r.result.error?.code], ['failed', 'OUTPUT_LIMIT']);
      assertEquals(r.result.steps[0].truncated, true);
      assert(r.result.steps[0].output.length <= 64 * 1024);
      assertEquals(h.mock.commands, ['systeminfo']);
      assertEquals(h.mock.signals, ['systeminfo']);
      assertEquals(h.mock.deletes.length, 1);
    }),
});

Deno.test({
  name: 'winrm exec: a command that never ends times out, is terminated and the shell is deleted',
  ...sanitize,
  fn: () =>
    withMock({ hang: /^systeminfo$/ }, async (h) => {
      const r = await runMode('exec', h, { pin: 'match', steps: ['systeminfo', 'ver'] });
      assertEquals([r.result.status, r.result.error?.code], ['failed', 'COMMAND_TIMEOUT']);
      assertEquals(r.result.steps[0].exitCode, 124);
      assertEquals(h.mock.signals, ['systeminfo']);
      assertEquals(h.mock.deletes.length, 1);
      assertEquals(h.mock.commands, ['systeminfo']);
    }),
});

Deno.test({
  name: 'winrm exec: cancellation terminates the command, deletes the shell and reports the abort',
  ...sanitize,
  fn: () =>
    withMock({ hang: /^systeminfo$/ }, async (h) => {
      const { session, api } = build('exec', h.mock.port, h, {
        pin: 'match',
        steps: ['systeminfo'],
      });
      session.start();
      const end = Date.now() + 15000;
      while (h.mock.commands.length === 0 && Date.now() < end) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assertEquals(h.mock.commands, ['systeminfo']);
      session.close('cancelled');
      await session.done;
      const result = api.results[0];
      assertEquals([result.status, result.error?.code], ['failed', 'EXEC_ABORTED']);
      assertEquals(h.mock.signals, ['systeminfo']);
      assertEquals(h.mock.deletes.length, 1);
      assertEquals(h.mock.openShells.size, 0);
      assertEquals(api.finished?.reason, 'cancelled');
    }),
});

Deno.test('winrm exec: changes and rotations are refused by the contract (no automatic change)', () => {
  const id = ASSIGNMENT.connectionUUID;
  for (const kind of ['change', 'rotate'] as const) {
    assertThrows(() => {
      const base: ExecPayload = {
        kind,
        requestUUID: id.replaceAll('-', ''),
        steps: kind === 'rotate' ? [] : ['ver'],
        verify: ['ver'],
        rollback: [],
        safeChange: 'reload_in',
        rollbackSeconds: 300,
        backupName: 'pre-ai-1',
        changeLog: null,
        sha256: '',
      };
      parseAssignment({
        ...ASSIGNMENT,
        mode: 'exec',
        ticket: null,
        protocol: 'winrm',
        shellDialect: 'windows',
        target: { address: '203.0.113.10', port: 5986 },
        exec: { ...base, sha256: execSha256(base) },
      });
    }, /Invalid exec/);
  }
});

// ---------------------------------------------------------------------------------------------
// Console

class FakeBrowser {
  readyState = 1;
  frames: string[] = [];
  closed: [number, string] | null = null;
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  send(data: string) {
    this.frames.push(data);
  }
  close(code = 1000, reason = '') {
    this.closed = [code, reason];
    this.readyState = 3;
  }
  type(data: string) {
    this.onmessage?.(
      { data: `0:${new TextEncoder().encode(data).length}:${data}` } as MessageEvent,
    );
  }
  frame(raw: string) {
    this.onmessage?.({ data: raw } as MessageEvent);
  }
  output() {
    return this.frames.map(parseServerFrame).filter((f) => f?.kind === 'output').map((f) =>
      (f as { data: string }).data
    ).join('');
  }
  controls() {
    return this.frames.map(parseServerFrame).filter((f) => f?.kind === 'control').map((f) =>
      (f as { message: { type: string } }).message
    );
  }
  async waitFor(predicate: () => boolean, ms = 15000) {
    const end = Date.now() + ms;
    while (!predicate()) {
      if (Date.now() > end) throw new Error(`timeout; output: ${this.output().slice(-400)}`);
      await new Promise((r) => setTimeout(r, 20));
    }
  }
}

async function console_(
  h: Harness,
  level: 'n1' | 'n2' | 'n3',
  options: Parameters<typeof build>[3] = {},
) {
  const { session, api } = build('console', h.mock.port, h, { pin: 'match', level, ...options });
  const browser = new FakeBrowser();
  session.attachBrowser(browser);
  await browser.waitFor(() => browser.frames.includes('OK'));
  return { session, api, browser };
}

Deno.test({
  name:
    'winrm console: lines go through the classifier, redaction and recording; one WinRS command per line',
  ...sanitize,
  fn: () =>
    withMock({
      commands: {
        hostname: { stdout: `SRV leaks ${PASSWORD}\r\n` },
        'echo hi': { stdout: 'hi\r\n' },
      },
    }, async (h) => {
      const { session, api, browser } = await console_(h, 'n3');
      assertEquals(api.calls.slice(0, 3), ['hostkey:tls:match', 'credential', 'result:used']);
      await browser.waitFor(() => browser.output().includes('Windows command shell'));
      // read: runs at once, echoed, output redacted
      browser.type('hostname\r');
      await browser.waitFor(() => browser.output().includes('SRV leaks'));
      assertNotIncludes(browser.output(), PASSWORD);
      assertEquals(h.mock.commands, ['hostname']);
      // composition and pivots are classified, not run: n3 needs a confirmation each
      browser.type('hostname & shutdown /s\r');
      await browser.waitFor(() => browser.controls().some((c) => c.type === 'verdict'));
      const verdict = browser.controls().find((c) => c.type === 'verdict') as unknown as {
        id: string;
        class: string;
        unknown: boolean;
      };
      assertEquals([verdict.class, verdict.unknown], ['write_risky', true]);
      await new Promise((r) => setTimeout(r, 200));
      assertEquals(h.mock.commands, ['hostname'], 'nothing runs before the confirmation');
      browser.frame(`4:${JSON.stringify({ type: 'deny', id: verdict.id })}`);
      await browser.waitFor(() => browser.controls().some((c) => c.type === 'resolved'));
      // a risky line that is confirmed runs as ONE command
      browser.type('echo hi\r');
      await browser.waitFor(() =>
        browser.controls().filter((c) => c.type === 'verdict').length === 2
      );
      const second = browser.controls().filter((c) => c.type === 'verdict')[1] as unknown as {
        id: string;
      };
      browser.frame(`4:${JSON.stringify({ type: 'confirm', id: second.id })}`);
      await browser.waitFor(() => browser.output().includes('hi\r\n'));
      assertEquals(h.mock.commands, ['hostname', 'echo hi']);
      // secrets are blocked outright, also at n3
      browser.type('set\r');
      await browser.waitFor(() => browser.controls().some((c) => c.type === 'blocked'));
      assertEquals(h.mock.commands, ['hostname', 'echo hi']);
      session.close('operator_closed');
      await session.done;
      // the shell was deleted on close
      assertEquals(h.mock.deletes.length, 1);
      const all = browser.frames.join('\n') + JSON.stringify(api.received) +
        api.parts.map((p) => new TextDecoder().decode(p)).join('') + JSON.stringify(api.finished);
      assertNotIncludes(all, PASSWORD);
      assert(api.parts.length > 0, 'recording uploaded');
      assert(api.received.some((e) =>
        e.type === 'command' && e.line === 'hostname' && e.verdict === 'allowed'
      ));
      assert(api.received.some((e) =>
        e.type === 'command' && e.verdict === 'denied'
      ));
      assert(api.received.some((e) => e.type === 'command' && e.verdict === 'confirmed'));
      assert(api.received.some((e) => e.type === 'command' && e.verdict === 'blocked'));
    }),
});

Deno.test({
  name: 'winrm console: at N1/N2 writes are blocked; an edited or escaped line is never run',
  ...sanitize,
  fn: () =>
    withMock({ commands: { hostname: { stdout: 'SRV\r\n' } } }, async (h) => {
      const { session, browser } = await console_(h, 'n2');
      browser.type('net user a b /add\r');
      await browser.waitFor(() => browser.controls().some((c) => c.type === 'blocked'));
      browser.type('powershell\r');
      await browser.waitFor(() =>
        browser.controls().filter((c) => c.type === 'blocked').length === 2
      );
      assertEquals(h.mock.commands, []);
      // Backspace is followed; arrows/history/Tab taint the line: unknown, blocked at N2.
      browser.type('hostnamex\x7f\r');
      await browser.waitFor(() => browser.output().includes('SRV'));
      browser.type('hostname\x1b[A\r');
      await browser.waitFor(() =>
        browser.controls().filter((c) => c.type === 'blocked').length === 3
      );
      assertEquals(h.mock.commands, ['hostname']);
      session.close('operator_closed');
      await session.done;
    }),
});

Deno.test({
  name: 'winrm console: at N3 a confirmed tainted line is still dropped by the line device',
  ...sanitize,
  fn: () =>
    withMock({ commands: { hostname: { stdout: 'SRV\r\n' } } }, async (h) => {
      const { session, browser } = await console_(h, 'n3');
      browser.type('hostname\x1b[D\r');
      await browser.waitFor(() => browser.controls().some((c) => c.type === 'verdict'));
      const verdict = browser.controls().find((c) => c.type === 'verdict') as unknown as {
        id: string;
      };
      browser.frame(`4:${JSON.stringify({ type: 'confirm', id: verdict.id })}`);
      await browser.waitFor(() => browser.output().includes('Line not executed'));
      assertEquals(h.mock.commands, []);
      session.close('operator_closed');
      await session.done;
    }),
});

Deno.test({
  name: 'winrm console: Ctrl+C terminates a running command and returns the prompt',
  ...sanitize,
  fn: () =>
    withMock({ hang: /^systeminfo$/ }, async (h) => {
      const { session, browser } = await console_(h, 'n2');
      browser.type('systeminfo\r');
      await browser.waitFor(() => h.mock.commands.length === 1);
      browser.type('\x03');
      await browser.waitFor(() => h.mock.signals.length === 1);
      await browser.waitFor(() => browser.output().includes('[command cancelled]'));
      assertEquals(h.mock.signals, ['systeminfo']);
      session.close('operator_closed');
      await session.done;
      assertEquals(h.mock.deletes.length, 1);
    }),
});

Deno.test({
  name: 'winrm console: output over the session limit ends the connection and deletes the shell',
  ...sanitize,
  fn: () =>
    withMock({
      commands: { systeminfo: { stdoutBytes: new Uint8Array(300 * 1024).fill(66) } },
    }, async (h) => {
      const { session, api, browser } = await console_(h, 'n2', {
        limits: { maxOutputBytes: 65536 },
      });
      browser.type('systeminfo\r');
      await session.done;
      assertEquals(api.finished?.reason, 'output_limit');
      assertEquals(h.mock.deletes.length, 1);
      assertEquals(h.mock.openShells.size, 0);
    }),
});

Deno.test({
  name: 'winrm console: auth failure, pin mismatch and a hostile reply end before a prompt',
  ...sanitize,
  fn: async () => {
    await withMock({}, async (h) => {
      const { session, api } = build('console', h.mock.port, h, { pin: 'mismatch' });
      session.attachBrowser(new FakeBrowser());
      await session.done;
      assertEquals(api.finished?.reason, 'hostkey_mismatch');
      assertEquals(h.mock.requests.length, 0);
    });
    await withMock({}, async (h) => {
      const { session, api } = build('console', h.mock.port, h, {
        pin: 'match',
        password: 'wrong',
      });
      const browser = new FakeBrowser();
      session.attachBrowser(browser);
      await session.done;
      assertEquals(api.finished?.reason, 'auth_failed');
      assertEquals(browser.closed?.[0], 4401);
    });
    await withMock({ failCreate: 'html' }, async (h) => {
      const { session, api } = build('console', h.mock.port, h, { pin: 'match' });
      session.attachBrowser(new FakeBrowser());
      await session.done;
      assertEquals(api.finished?.reason, 'protocol_error');
    });
  },
});

Deno.test('winrm XML rejects duplicate attributes, unbound prefixes and aliased closing tags', () => {
  for (
    const xml of [
      '<a x="1" x="2"/>',
      '<p:a/>',
      '<p:a xmlns:p="urn:x" xmlns:q="urn:x"></q:a>',
      '<a xmlns:p="urn:x" xmlns:q="urn:x" p:x="1" q:x="2"/>',
    ]
  ) assertThrows(() => parseXml(xml));
});

Deno.test('winrm close settles pending request and closes transport once', async () => {
  let closes = 0;
  const wire = scripted([[]]);
  const original = wire.transport.close;
  wire.transport.close = () => {
    closes++;
    original();
  };
  const conn = new HttpConnection(wire.transport, 'fixture:5986', 'Basic synthetic');
  const pending = conn.request('synthetic', 10000);
  conn.close();
  conn.close();
  await assertRejects(() => pending, /Closed/);
  await new Promise((resolve) => setTimeout(resolve, 5));
  assertEquals(closes, 1);
});

Deno.test('winrm integral deadline and cancellation suppress Command and late Receive output', async () => {
  for (const stage of ['pre', 'command', 'receive', 'cancel-receive']) {
    let starts = 0, receives = 0, output = 0, cancelled = stage === 'pre';
    const client = {
      startCommand: async () => {
        starts++;
        if (stage === 'command') await new Promise((r) => setTimeout(r, 30));
        return 'id';
      },
      receive: async () => {
        receives++;
        if (stage === 'receive') await new Promise((r) => setTimeout(r, 30));
        if (stage === 'cancel-receive') cancelled = true;
        return {
          done: true,
          exitCode: 0,
          chunks: [{ stream: 'stdout', bytes: new Uint8Array([65]) }],
        };
      },
      terminate: () => Promise.resolve(),
    } as unknown as WsmanClient;
    const result = await runWinrmCommand(client, 'shell', 'hostname', {
      timeoutMs: stage === 'cancel-receive' ? 1000 : 10,
      maxBytes: 100,
      cancelled: () => cancelled,
      onChunk: () => {
        output++;
      },
    });
    assertEquals(output, 0);
    assertEquals(starts, stage === 'pre' ? 0 : 1);
    assertEquals(receives, ['pre', 'command'].includes(stage) ? 0 : 1);
    assertEquals(result.cancelled, ['pre', 'cancel-receive'].includes(stage));
    assertEquals(result.timedOut, ['command', 'receive'].includes(stage));
  }
});

Deno.test({
  name:
    'winrm real worker rejects namespace, Action, duplicate correlation and conflicting shell IDs',
  ...sanitize,
  fn: async () => {
    const mutations = [
      (xml: string) => xml.replace('http://www.w3.org/2003/05/soap-envelope', 'urn:wrong'),
      (xml: string) => xml.replace('http://schemas.xmlsoap.org/ws/2004/08/addressing', 'urn:wrong'),
      (xml: string) =>
        xml.replace('http://schemas.microsoft.com/wbem/wsman/1/windows/shell', 'urn:wrong'),
      (xml: string) => xml.replace('transfer/CreateResponse', 'transfer/DeleteResponse'),
      (xml: string) => xml.replace(/(<a:RelatesTo>.*?<\/a:RelatesTo>)/, '$1$1'),
      (xml: string) =>
        xml.replace(
          '</rsp:Shell>',
          '<rsp:ShellId>11111111-2222-4333-8444-555555555555</rsp:ShellId></rsp:Shell>',
        ),
      (xml: string) =>
        xml.replace(
          '</s:Body>',
          '<t:ResourceCreated xmlns:t="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters><w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="OtherId">11111111-2222-4333-8444-555555555555</w:Selector></w:SelectorSet></a:ReferenceParameters></t:ResourceCreated></s:Body>',
        ),
    ];
    for (const mutate of mutations) {
      await withMock({
        transformResponse: (xml, action) => action === 'create' ? mutate(xml) : xml,
      }, async (h) => {
        const { result, reason } = await runMode('exec', h);
        assertEquals(result.status, 'failed');
        assertEquals(reason, 'protocol_error');
        assertEquals(h.mock.commands.length, 0);
      });
    }
  },
});

Deno.test({
  name: 'winrm real worker never exposes fault code text as result metadata',
  ...sanitize,
  fn: async () => {
    await withMock({
      failReceive: 'fault',
      transformResponse: (xml, action) =>
        action === 'receive'
          ? xml.replace('Code="2150858780"', 'Code="synthetic-secret-do-not-leak"')
          : xml,
    }, async (h) => {
      const { result } = await runMode('exec', h);
      assertEquals(result.error?.code, 'WINRM_FAULT_unknown');
      assertNotIncludes(JSON.stringify(result), 'synthetic-secret-do-not-leak');
      assertEquals(h.mock.openShells.size, 0);
    });
  },
});

Deno.test({
  name: 'winrm real worker cancelled during pin decision never requests a credential or sends SOAP',
  ...sanitize,
  fn: async () => {
    await withMock({}, async (h) => {
      const { session, api } = build('exec', h.mock.port, h);
      api.hostKey = async () => {
        session.close('cancelled');
        await new Promise((r) => setTimeout(r, 30));
        return { decision: 'accept', pinned: true };
      };
      session.start();
      await session.done;
      assertEquals(api.calls.includes('credential'), false);
      assertEquals(h.mock.requests.length, 0);
    });
  },
});

Deno.test('winrm WS-Man request timeout bounds Create', async () => {
  const wire = scripted([[]]);
  const http = new HttpConnection(wire.transport, 'fixture:5986', 'Basic synthetic');
  const client = new WsmanClient(http, 'https://fixture:5986/wsman', 5);
  const started = Date.now();
  await assertRejects(() => client.createShell(), /in time/);
  assert(Date.now() - started < 1000);
  assert(wire.closed());
});

Deno.test({
  name: 'winrm real worker cancellation while unwrap waits never sends Basic or Create',
  ...sanitize,
  fn: async () => {
    await withMock({}, async (h) => {
      const built = build('exec', h.mock.port, h, {
        unwrap: async () => {
          built.session.close('cancelled');
          await new Promise((r) => setTimeout(r, 40));
          return { username: 'support', password: PASSWORD };
        },
      });
      const session = built.session;
      session.start();
      await session.done;
      assert(built.api.calls.includes('credential'));
      assertEquals(h.mock.requests.length, 0);
      assertEquals(h.mock.commands.length, 0);
      assert(built.api.calls.includes('result:unused'));
    });
  },
});

Deno.test({
  name:
    'winrm real worker accepts named ShellID selector and rejects conflicting or duplicated operation IDs',
  ...sanitize,
  fn: async () => {
    const selector = (id: string) =>
      `<t:ResourceCreated xmlns:t="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:ReferenceParameters><w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><w:Selector Name="ShellID">${id}</w:Selector></w:SelectorSet></a:ReferenceParameters></t:ResourceCreated>`;
    await withMock({
      transformResponse: (xml, action) =>
        action === 'create'
          ? xml.replace(
            /<rsp:Shell><rsp:ShellId>(.*?)<\/rsp:ShellId><\/rsp:Shell>/,
            (_, id) => selector(id),
          )
          : xml,
    }, async (h) => {
      const r = await runMode('test', h);
      assertEquals(r.reason, 'test_ok');
      assertEquals(h.mock.openShells.size, 0);
    });
    for (const stage of ['create', 'command', 'receive']) {
      await withMock({
        commands: { ver: { stdout: 'version' } },
        transformResponse: (xml, action) => {
          if (action !== stage) return xml;
          if (stage === 'create') {
            return xml.replace(
              '</s:Body>',
              selector('11111111-2222-4333-8444-555555555555') + '</s:Body>',
            );
          }
          if (stage === 'command') {
            return xml.replace(/(<rsp:CommandId>.*?<\/rsp:CommandId>)/, '$1$1');
          }
          return xml.replace(/(<rsp:CommandState .*?<\/rsp:CommandState>)/, '$1$1');
        },
      }, async (h) => {
        const r = await runMode('exec', h);
        assertEquals(r.result.status, 'failed');
        assertEquals(r.result.steps.length, 0);
      });
    }
  },
});
