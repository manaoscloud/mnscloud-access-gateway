// Integration: controller Session + real sandboxed-flag worker process (Deno --allow-net limited to
// the device) + hostile fake SSH device + fake control plane. No systemd/netns here (those are
// rendered and unit-tested in network_test.ts).

import { parseAssignment } from '../src/controller/contract.ts';
import type { RuntimeEvent, SessionApi } from '../src/controller/session.ts';
import { Session } from '../src/controller/session.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import { parseServerFrame } from '../src/shared/framing.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { assert, assertEquals, assertNotIncludes } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import {
  type Behaviour,
  fingerprintOf,
  generateHostKey,
  PASSWORD,
  startDevice,
} from './hostile_ssh_server.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

class FakeApi implements SessionApi {
  calls: string[] = [];
  received: RuntimeEvent[] = [];
  parts: Uint8Array[] = [];
  finished: FinishBody | null = null;
  credentialResults: string[] = [];
  constructor(private readonly pin: 'accept' | 'block' = 'accept') {}
  hostKey(_c: string, body: { result: string }) {
    this.calls.push(`hostkey:${body.result}`);
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
    this.credentialResults.push(body.result);
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
  finish(_c: string, body: FinishBody) {
    this.finished = body;
    this.calls.push(`finish:${body.reason}`);
    return Promise.resolve();
  }
}

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
      if (Date.now() > end) {
        throw new Error(`timeout; frames: ${JSON.stringify(this.frames.slice(-8)).slice(0, 800)}`);
      }
      await new Promise((r) => setTimeout(r, 20));
    }
  }
}

async function open(options: {
  behaviour?: Behaviour;
  pinned?: 'match' | 'mismatch' | null;
  pin?: 'accept' | 'block';
  level?: 'n1' | 'n2' | 'n3';
  dialect?: string;
  limits?: Record<string, number>;
}) {
  const key = generateHostKey();
  const device = await startDevice(key, options.behaviour ?? 'normal');
  const pinned = options.pinned === 'match'
    ? fingerprintOf(key)
    : options.pinned === 'mismatch'
    ? fingerprintOf(generateHostKey())
    : null;
  const api = new FakeApi(options.pin);
  const assignment = parseAssignment({
    ...ASSIGNMENT,
    connectionUUID: crypto.randomUUID(),
    target: { address: '127.0.0.1', port: device.port },
    username: 'support',
    level: options.level ?? 'n2',
    shellDialect: options.dialect ?? 'routeros',
    hostKey: { pinned },
    limits: { ...ASSIGNMENT.limits, ...(options.limits ?? {}) },
    recording: { enabled: true, partBytes: 65536, partSeconds: 5 },
  });
  const logs: string[] = [];
  const session = new Session(assignment, {
    api,
    unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
    launcher: new DirectLauncher(ROOT),
    networks: null,
    sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
    log: (m) => logs.push(m),
  });
  const browser = new FakeBrowser();
  session.attachBrowser(browser);
  return { session, browser, api, device, logs };
}

function everything(api: FakeApi, browser: FakeBrowser) {
  return browser.frames.join('\n') + JSON.stringify(api.received) +
    api.parts.map((p) => new TextDecoder().decode(p)).join('') +
    JSON.stringify(api.finished);
}

Deno.test({
  name:
    'session: TOFU host key is reported before the credential is pulled; secrets never leave the worker',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, browser, api, device } = await open({ pinned: null });
    await browser.waitFor(() => browser.frames.includes('OK'));
    assertEquals(api.calls.slice(0, 2), ['hostkey:unpinned', 'credential']);
    browser.type('/export\r');
    await browser.waitFor(() => browser.output().includes('service=pppoe'));
    browser.type(':put secret\r');
    await browser.waitFor(() => browser.output().includes(' ok'));
    browser.frame('1:100:40:');
    browser.type('/quit\r');
    await session.done;
    const all = everything(api, browser);
    assertNotIncludes(all, PASSWORD);
    assertNotIncludes(all, 'ppp-secret-1');
    assertNotIncludes(all, PASSWORD.slice(5));
    assertEquals(api.finished?.reason, 'device_closed');
    assertEquals(api.credentialResults, ['used']);
    assert(api.parts.length > 0, 'recording uploaded');
    const cast = api.parts.map((p) => new TextDecoder().decode(p)).join('').split('\n').filter(
      Boolean,
    ).map((l) => JSON.parse(l));
    assertEquals(cast[0].version, 2);
    assert(
      cast.some((e) => e[1] === 'm' && String(e[2]).includes('/export')),
      'marker of the command',
    );
    assert(cast.some((e) => e[1] === 'r' && e[2] === '100x40'), 'resize event');
    assert(
      api.received.some((e) =>
        e.type === 'command' && e.line === '/export' && e.verdict === 'allowed'
      ),
    );
    assert(device.received.join('').includes('/export\r'));
    await device.close();
  },
});

Deno.test({
  name: 'session: host key mismatch blocks before any authentication',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, browser, api, device } = await open({ pinned: 'mismatch' });
    await session.done;
    assertEquals(api.calls.includes('credential'), false);
    assertEquals(device.authAttempts, 0);
    assertEquals(api.finished?.reason, 'hostkey_mismatch');
    assertEquals(browser.closed?.[0], 4409);
    assert(
      browser.controls().some((c) =>
        c.type === 'hostkey' && (c as unknown as { result: string }).result === 'mismatch'
      ),
    );
    await device.close();
  },
});

Deno.test({
  name: 'session: an unpinned key the API refuses to pin is blocked',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, api, device } = await open({ pinned: null, pin: 'block' });
    await session.done;
    assertEquals(api.calls.includes('credential'), false);
    assertEquals(api.finished?.reason, 'hostkey_rejected');
    await device.close();
  },
});

Deno.test({
  name: 'session: output flood is throttled and ends at the output limit',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, browser, api, device } = await open({
      pinned: 'match',
      behaviour: 'flood',
      limits: { maxOutputBytes: 2 * 1024 * 1024, maxOutputBytesPerSecond: 1024 * 1024 },
    });
    await session.done;
    assertEquals(api.finished?.reason, 'output_limit');
    assertEquals(browser.closed?.[0], 4413);
    assert(browser.controls().some((c) => c.type === 'notice'), 'throttle notice');
    await device.close();
  },
});

Deno.test({
  name: 'session: hostile escape sequences are stripped and injected text stays output',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    for (const behaviour of ['escapes', 'inject'] as Behaviour[]) {
      const { session, browser, api, device } = await open({ pinned: 'match', behaviour });
      await browser.waitFor(() => browser.output().includes('[support@device] > '));
      const output = browser.output();
      for (const bad of ['\x1b]52', '\x1b]0;', '\x1bP', '\x1b]8;']) {
        assertNotIncludes(output, bad, behaviour);
      }
      if (behaviour === 'escapes') assert(output.includes('\x1b[31mred'), 'colors kept');
      if (behaviour === 'inject') {
        assert(output.includes('3:{"type":"verdict"'), 'injected text is plain output');
        assertEquals(browser.controls().filter((c) => c.type === 'verdict').length, 0);
      }
      browser.type('/quit\r');
      await session.done;
      assertEquals(api.finished?.state, 'closed');
      await device.close();
    }
  },
});

Deno.test({
  name: 'session: writes wait for the App confirmation frame',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, browser, api, device } = await open({ pinned: 'match', level: 'n3' });
    await browser.waitFor(() => browser.frames.includes('OK'));
    browser.type('/system reboot\r');
    await browser.waitFor(() => browser.controls().some((c) => c.type === 'verdict'));
    const verdict = browser.controls().find((c) => c.type === 'verdict') as unknown as {
      id: string;
      class: string;
    };
    assertEquals(verdict.class, 'write_risky');
    await new Promise((r) => setTimeout(r, 200));
    assertEquals(device.received.join('').includes('/system reboot\r'), false);
    browser.frame(`4:${JSON.stringify({ type: 'confirm', id: verdict.id })}`);
    await browser.waitFor(() => device.received.join('').includes('/system reboot\r'));
    browser.type('/quit\r');
    await session.done;
    assert(api.received.some((e) => e.type === 'command' && e.verdict === 'confirmed'));
    await device.close();
  },
});

Deno.test({
  name: 'session: a killed worker still finishes the connection',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { session, browser, api, device } = await open({ pinned: 'match' });
    await browser.waitFor(() => browser.frames.includes('OK'));
    // Kill the worker process abruptly (what an OOM kill or crash would do).
    // deno-lint-ignore no-explicit-any
    await ((session as any).worker as { kill(): Promise<void> }).kill();
    await session.done;
    assert(api.finished !== null);
    await device.close();
  },
});
