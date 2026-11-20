// Protocol tests of the Junos NETCONF change (src/worker/junos). The channel is a scripted
// synthetic server in the wire shapes of the Juniper documentation and YANG modules: it proves the
// state machine and the fail-closed branches, NOT that any firmware behaves this way. Source
// provenance of the observer profile: tests/fixtures/junos/observer-sources.json.

import { change, type Hooks, type Options } from '../src/worker/junos/change.ts';
import {
  BASE,
  CAP,
  type Channel,
  JUNOS,
  NC,
  Netconf,
  type PinnedClient,
} from '../src/worker/junos/netconf.ts';
import { configDigest, lockOwner, MON } from '../src/worker/junos/observe.ts';
import { escapeXml, MAX_FRAME, parseXml } from '../src/worker/junos/xml.ts';
import { assert, assertEquals } from './assert.ts';
// Device-side directory of the backup files (a path on the router, never created locally).
const DEVICE_DIR = ['', 'var', 'tmp', ''].join('/');
const bytes = (s: string) => new TextEncoder().encode(s);
const caps = [
  BASE,
  CAP + 'candidate:1.0',
  CAP + 'confirmed-commit:1.1',
  CAP + 'validate:1.1',
  JUNOS,
];
class Mock implements Channel, PinnedClient {
  calls: string[] = [];
  closed = false;
  capabilities = caps;
  handler: ((body: string, id: string) => string | null) | null = null;
  fragment = false;
  events = new Map<string, ((...args: unknown[]) => void)[]>();
  // The synthetic emitter exposes only the three Channel event signatures used by transport.
  on(event: 'data', cb: (b: Uint8Array) => void): void;
  on(event: 'error', cb: (e: unknown) => void): void;
  on(event: 'close' | 'end', cb: () => void): void;
  on(event: string, cb: unknown) {
    this.events.set(event, [
      ...(this.events.get(event) ?? []),
      cb as (...args: unknown[]) => void,
    ]);
  }
  emit(event: string, ...args: unknown[]) {
    for (const cb of this.events.get(event) ?? []) cb(...args);
  }
  subsys(name: string, cb: (e: Error | undefined, c: Channel) => void) {
    assertEquals(name, 'netconf');
    cb(undefined, this);
  }
  send(xml: string) {
    const b = bytes(xml + ']]>]]>');
    queueMicrotask(() => {
      if (this.closed) return;
      if (this.fragment) {
        this.emit('data', b.subarray(0, 7));
        this.emit('data', b.subarray(7));
      } else this.emit('data', b);
    });
  }
  write(s: string) {
    if (s.startsWith('<hello')) {
      this.send(
        `<hello xmlns="${NC}"><capabilities>${
          this.capabilities.map((c) => `<capability>${escapeXml(c)}</capability>`).join('')
        }</capabilities><session-id>123</session-id></hello>`,
      );
      return;
    }
    const id = /message-id="(\d+)"/.exec(s)![1];
    const body = s.slice(s.indexOf('>') + 1, s.lastIndexOf('</rpc>'));
    this.calls.push(body);
    if (this.handler) {
      const value = this.handler(body, id);
      if (value === null) return;
      if (value) {
        this.send(value);
        return;
      }
    }
    this.send(
      reply(
        id,
        body.startsWith('<load-configuration')
          ? '<load-configuration-results><ok/></load-configuration-results>'
          : '<ok/>',
      ),
    );
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.emit('close');
  }
}
const reply = (id: string, body = '<ok/>', ns = NC) =>
  `<rpc-reply xmlns="${ns}" message-id="${id}">${body}</rpc-reply>`;
function options(
  overrides: Partial<Options> = {},
  events: string[] = [],
): Options {
  const hooks: Hooks = {
    observe: async (_nc, phase) => {
      await Promise.resolve();
      events.push(phase);
      return {
        lockHeld: true,
        pending: phase === 'before' || phase === 'loaded' || phase === 'after-confirm'
          ? 'none'
          : 'ours',
        baselineRestored: false,
      };
    },
    backup: async (phase, file) => {
      await Promise.resolve();
      events.push('backup-' + phase);
      assert(file.startsWith(DEVICE_DIR + 'stk-'));
    },
    verify: async () => {
      await Promise.resolve();
      events.push('verify');
      return true;
    },
  };
  return {
    commands: ['set interfaces ge-0/0/1 description "test fixture"'],
    backupName: 'stk-fixture-12345678',
    rollbackSeconds: 120,
    signal: new AbortController().signal,
    hooks,
    ...overrides,
  };
}
Deno.test('wire success: exact lifecycle, backups around native confirmed commit, no persist or rollback1', async () => {
  const m = new Mock();
  m.fragment = true;
  const events: string[] = [];
  const r = await change(m, options({}, events));
  assertEquals(r.state, 'confirmed');
  assertEquals(events, [
    'before',
    'backup-pre',
    'loaded',
    'pending',
    'backup-post',
    'verify',
    'before-confirm',
    'after-confirm',
  ]);
  assertEquals(m.calls.map((c) => /^<([^ >]+)/.exec(c)![1]), [
    'lock',
    'load-configuration',
    'validate',
    'commit',
    'commit/',
    'unlock',
  ]);
  assert(
    m.calls[3].includes('<confirmed/>') &&
      !m.calls.join('').includes('persist'),
  );
  assert(m.closed);
  assert(!m.calls.join('').includes('rollback'));
});
Deno.test('dirty candidate/lock denied does not discard, load, backup or verify', async () => {
  const m = new Mock();
  m.handler = (_b, id) =>
    reply(
      id,
      '<rpc-error><error-tag>lock-denied</error-tag><error-message>secret device content</error-message></rpc-error>',
    );
  const e: string[] = [];
  const r = await change(m, options({}, e));
  assertEquals(r.code, 'LOCK_REFUSED');
  assertEquals(r.state, 'refused');
  assertEquals(e, []);
  assertEquals(m.calls.length, 1);
  assert(!JSON.stringify(r).includes('secret'));
});
Deno.test('capability refusal occurs before lock', async () => {
  const m = new Mock();
  m.capabilities = [BASE];
  const r = await change(m, options());
  assertEquals(r.code, 'UNSUPPORTED_CAPABILITY');
  assertEquals(m.calls, []);
});
Deno.test('wrong reply namespace fails closed before backup', async () => {
  const m = new Mock();
  m.handler = (_b, id) => reply(id, '<ok/>', 'urn:wrong');
  const r = await change(m, options());
  assertEquals(r.code, 'REPLY_MISMATCH');
  assertEquals(m.calls.length, 1);
});
Deno.test('mismatched rpc message id rejected', async () => {
  const m = new Mock();
  m.handler = () => reply('999');
  const r = await change(m, options());
  assertEquals(r.code, 'REPLY_MISMATCH');
});
Deno.test('RPC error after load is sanitized and session closes without commit', async () => {
  const m = new Mock();
  m.handler = (b, id) =>
    b.startsWith('<load')
      ? reply(
        id,
        '<rpc-error><error-tag>operation-failed</error-tag><error-info>password=test-secret</error-info></rpc-error>',
      )
      : '';
  const r = await change(m, options());
  assertEquals(r.state, 'failed');
  assertEquals(r.code, 'RPC_ERROR');
  assert(!m.calls.some((c) => c.startsWith('<commit')));
  assert(!JSON.stringify(r).includes('test-secret'));
});
Deno.test('lost confirming reply is unknown, never confirmed or rolled_back', async () => {
  const m = new Mock();
  m.handler = (b) => b === '<commit/>' ? null : '';
  const r = await change(m, options({ requestTimeoutMs: 10 }));
  assertEquals(r.state, 'unknown');
  assertEquals(r.code, 'TIMEOUT');
  assert(r.confirmationSent && m.closed);
});
Deno.test('timer budget expires during verification: never confirm or rollback1', async () => {
  const m = new Mock();
  let now = 0;
  const o = options({ now: () => now });
  o.hooks.verify = async () => {
    await Promise.resolve();
    now = 120000;
    return true;
  };
  const r = await change(m, o);
  assertEquals(r.state, 'rollback_pending');
  assertEquals(r.code, 'DEADLINE');
  assert(!m.calls.includes('<commit/>'));
  assert(m.closed);
});
Deno.test('lost exclusive ownership after timer: refuse confirmation', async () => {
  const m = new Mock();
  const o = options();
  o.hooks.observe = (_nc, phase) =>
    Promise.resolve({
      lockHeld: phase !== 'before-confirm',
      pending: phase === 'before' || phase === 'loaded' ? 'none' : 'ours',
      baselineRestored: false,
    });
  const r = await change(m, o);
  assertEquals(r.code, 'COMMIT_OWNERSHIP_LOST');
  assertEquals(r.state, 'rollback_pending');
  assert(!m.calls.includes('<commit/>'));
});
Deno.test('post backup failure leaves rollback pending and never verifies/confirms', async () => {
  const m = new Mock();
  const events: string[] = [];
  const o = options({}, events);
  o.hooks.backup = async (p) => {
    await Promise.resolve();
    if (p === 'post') throw new Error('sensitive error');
  };
  const r = await change(m, o);
  assertEquals(r.state, 'rollback_pending');
  assertEquals(r.code, 'HOOK_FAILED');
  assert(!events.includes('verify'));
  assert(!m.calls.includes('<commit/>'));
});
Deno.test('foreign pending commit after lock refused with no backup/mutation', async () => {
  const m = new Mock();
  const o = options();
  o.hooks.observe = () =>
    Promise.resolve({
      lockHeld: true,
      pending: 'foreign',
      baselineRestored: false,
    });
  const r = await change(m, o);
  assertEquals(r.code, 'FOREIGN_OR_UNKNOWN_COMMIT');
  assertEquals(m.calls.length, 1);
});
Deno.test('cancellation before subsystem never contacts client', async () => {
  const m = new Mock();
  const ctl = new AbortController();
  ctl.abort();
  const r = await change(m, options({ signal: ctl.signal }));
  assertEquals(r.code, 'CANCELLED');
  assertEquals(m.calls, []);
});
Deno.test('cancellation in verification closes original session, no confirmation', async () => {
  const m = new Mock();
  const ctl = new AbortController();
  const o = options({ signal: ctl.signal });
  o.hooks.verify = async () => {
    await Promise.resolve();
    ctl.abort();
    return true;
  };
  const r = await change(m, o);
  assertEquals(r.state, 'rollback_pending');
  assert(!m.calls.includes('<commit/>') && m.closed);
});
Deno.test('grammar composition and invalid backup name refused before subsystem', async () => {
  for (
    const command of [
      'set interfaces ge-0/0/1 disable; commit',
      'rollback 1',
      'commit',
      'set interfaces ge-0/0/1 disable\ncommit',
    ]
  ) {
    const m = new Mock();
    const r = await change(m, options({ commands: [command] }));
    assertEquals(r.code, 'PRECONDITION');
    assertEquals(m.calls, []);
  }
  const m = new Mock();
  assertEquals(
    (await change(m, options({ backupName: '../escape' }))).code,
    'PRECONDITION',
  );
});
Deno.test('strict XML: namespace aliases work; duplicate expanded attrs/mismatched tags/DTD rejected', () => {
  const ok = parseXml(
    bytes(`<a:rpc-reply xmlns:a="${NC}" message-id="1"><a:ok/></a:rpc-reply>`),
  );
  assertEquals(ok.ns, NC);
  for (
    const s of [
      '<x a="1" a="2"/>',
      '<x xmlns:a="urn:x" xmlns:b="urn:x" a:k="1" b:k="2"/>',
      '<a:x xmlns:a="urn:x" xmlns:b="urn:x"></b:x>',
      '<!DOCTYPE a><a/>',
      '<a>&#0;</a>',
      '<a><b/></a><c/>',
    ]
  ) {
    let rejected = false;
    try {
      parseXml(bytes(s));
    } catch {
      rejected = true;
    }
    assert(rejected, s);
  }
  assertEquals(escapeXml('&<>"'), '&amp;&lt;&gt;&quot;');
});
Deno.test('bounded wire rejects oversize and unsolicited extra frame', async () => {
  for (const mode of ['large', 'extra']) {
    const m = new Mock();
    const nc = await Netconf.open(m, new AbortController().signal);
    m.handler = () => null;
    const p = nc.ok('<lock/>', new AbortController().signal, 100);
    if (mode === 'large') m.emit('data', new Uint8Array(MAX_FRAME + 7));
    else m.emit('data', bytes(reply('1') + ']]>]]>' + reply('2') + ']]>]]>'));
    let rejected = false;
    try {
      await p;
    } catch {
      rejected = true;
    }
    assert(rejected && m.closed);
  }
});
Deno.test('UTF8 decode is fatal', () => {
  let rejected = false;
  try {
    parseXml(new Uint8Array([60, 120, 62, 255, 60, 47, 120, 62]));
  } catch {
    rejected = true;
  }
  assert(rejected);
});

/** Synthetic values in wire shapes from Juniper docs/YANG; not captured device output. */
function observedMock(): Mock {
  const m = new Mock();
  m.capabilities = [...caps, MON];
  let loaded = false, pending = false, confirmed = false;
  const cfg = (changed: boolean) =>
    `<configuration xmlns:junos="http://xml.juniper.net/junos/23.4R1/junos" junos:commit-seconds="100"><interfaces><interface><name>ge-0/0/1</name><description>${
      changed ? 'test fixture' : 'before'
    }</description></interface></interfaces></configuration>`;
  m.handler = (body, id) => {
    if (body.startsWith('<load-configuration')) loaded = true;
    if (body.includes('<confirmed/>')) pending = true;
    if (body === '<commit/>') {
      pending = false;
      confirmed = true;
    }
    if (body.startsWith('<get><filter')) {
      return reply(
        id,
        `<data><netconf-state xmlns="${MON}"><datastores><datastore><name>candidate</name><locks><locked-by-session>123</locked-by-session><locked-time>2026-11-19T00:00:00Z</locked-time></locks></datastore><datastore><name>running</name></datastore></datastores></netconf-state></data>`,
      );
    }
    if (body.startsWith('<get-commit-information')) {
      return reply(
        id,
        `<commit-information><commit-history><sequence-number>0</sequence-number><user>fixture</user><client>netconf</client><configuration-revision>${
          pending || confirmed ? 're0-100-2' : 're0-100-1'
        }</configuration-revision>${
          pending ? '<commit-confirmed>rollback pending</commit-confirmed>' : ''
        }</commit-history></commit-information>`,
      );
    }
    if (body.startsWith('<get-configuration')) {
      return reply(
        id,
        cfg(
          body.includes('database="candidate"') ? loaded : pending || confirmed,
        ),
      );
    }
    return '';
  };
  return m;
}
function observedOptions(): Options {
  const o = options({ backupName: 'mns-rb-fixture-12345678' });
  delete o.hooks.observe;
  o.hooks.backup = async (_phase, path) => {
    await Promise.resolve();
    assert(path.startsWith(DEVICE_DIR + 'mns-rb-'));
  };
  return o;
}
Deno.test('fullSession uses concrete RPC observer, native digests, exact lock session and real callbacks', async () => {
  const m = observedMock();
  const r = await change(m, observedOptions());
  assertEquals(r.state, 'confirmed');
  assert(m.calls.filter((c) => c.startsWith('<get><filter')).length === 10);
  assert(
    m.calls.filter((c) => c.startsWith('<get-configuration')).length === 10,
  );
  assert(m.calls.includes('<commit/>'));
});
Deno.test('observed session refuses monitoring absence before backup or load', async () => {
  const m = observedMock();
  m.capabilities = caps;
  const r = await change(m, observedOptions());
  assertEquals(r.code, 'UNSUPPORTED_LOCK_MONITORING');
  assert(!m.calls.some((c) => c.startsWith('<load')));
});
Deno.test('observed session rejects foreign lock session ID', async () => {
  const m = observedMock();
  const h = m.handler!;
  m.handler = (b, id) => {
    const response = h(b, id);
    return response?.replace(
      '<locked-by-session>123',
      '<locked-by-session>99',
    ) ?? response;
  };
  const r = await change(m, observedOptions());
  assertEquals(r.code, 'LOCK_OWNERSHIP_LOST');
  assert(!m.calls.some((c) => c.startsWith('<load')));
});
Deno.test('observed session rejects unknown commit history fields', async () => {
  const m = observedMock();
  const h = m.handler!;
  m.handler = (b, id) =>
    h(b, id)?.replace(
      '</commit-history>',
      '<unknown-timer-state/></commit-history>',
    ) ?? null;
  const r = await change(m, observedOptions());
  assertEquals(r.code, 'OBSERVATION_SCHEMA_UNSUPPORTED');
  assert(!m.calls.some((c) => c.startsWith('<load')));
});
Deno.test('observed session rejects pending foreign transaction before load', async () => {
  const m = observedMock();
  const h = m.handler!;
  m.handler = (b, id) =>
    h(b, id)?.replace(
      '</commit-information>',
      '<pending-commit><user>other</user></pending-commit></commit-information>',
    ) ?? null;
  const r = await change(m, observedOptions());
  assertEquals(r.code, 'FOREIGN_PENDING_COMMIT');
  assert(!m.calls.some((c) => c.startsWith('<load')));
});
Deno.test('observed session rejects running content inconsistent with loaded candidate', async () => {
  const m = observedMock();
  const h = m.handler!;
  m.handler = (b, id) => {
    const response = h(b, id);
    return b.includes('database="committed"')
      ? response?.replace('test fixture', 'foreign change') ?? response
      : response;
  };
  const r = await change(m, observedOptions());
  assertEquals(r.code, 'CONFIGURATION_CHANGED_OR_REVERTED');
  assertEquals(r.state, 'rollback_pending');
  assert(!m.calls.includes('<commit/>'));
});
Deno.test('digest ignores documented root timing metadata only; semantic attribute and text change matters', async () => {
  const parse = (s: string) => parseXml(bytes(reply('1', s)));
  const c =
    '<configuration><interfaces><interface inactive="inactive"><name>ge-0/0/1</name></interface></interfaces></configuration>';
  const a = await configDigest(parse(c));
  const b = await configDigest(
    parse(
      c.replace(
        '<configuration>',
        '<configuration xmlns:junos="http://xml.juniper.net/junos/23.4R1/junos" junos:commit-seconds="1">',
      ),
    ),
  );
  assertEquals(a, b);
  assert(
    a !== await configDigest(parse(c.replace(' inactive="inactive"', ''))),
  );
  assert(a !== await configDigest(parse(c.replace('ge-0/0/1', 'ge-0/0/2'))));
});

Deno.test('documented XNM configuration payload works across full observed session', async () => {
  const m = observedMock();
  const h = m.handler!;
  m.handler = (b, id) =>
    h(b, id)?.replace(
      '<configuration xmlns:junos=',
      '<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" xmlns:junos=',
    ) ?? null;
  assertEquals((await change(m, observedOptions())).state, 'confirmed');
});
Deno.test('qualified YANG monitoring capability accepts correct module/revision and rejects impostors', async () => {
  for (
    const [suffix, expected] of [
      ['?module=ietf-netconf-monitoring&revision=2010-10-04', 'confirmed'],
      ['?module=other&revision=2010-10-04', 'refused'],
      ['?module=ietf-netconf-monitoring&module=other', 'refused'],
      ['/evil?module=ietf-netconf-monitoring', 'refused'],
    ]
  ) {
    const m = observedMock();
    m.capabilities = [...caps, MON + suffix];
    assertEquals((await change(m, observedOptions())).state, expected);
  }
});
Deno.test('undocumented history namespace and nested namespace substitution stay refused', async () => {
  for (const variant of ['root', 'child']) {
    const m = observedMock();
    const h = m.handler!;
    m.handler = (b, id) => {
      const r = h(b, id);
      return variant === 'root'
        ? r?.replace(
          '<commit-information>',
          '<commit-information xmlns="http://xml.juniper.net/junos/23.4R1/junos-system">',
        ) ?? r
        : r?.replace(
          '<configuration-revision>',
          '<configuration-revision xmlns="urn:impostor">',
        ) ?? r;
    };
    assertEquals(
      (await change(m, observedOptions())).code,
      'OBSERVATION_SCHEMA_UNSUPPORTED',
    );
    assert(!m.calls.some((c) => c.startsWith('<load')));
  }
});

Deno.test('official documentation fixtures parse with the strict profile (provenance manifest)', async () => {
  const read = (name: string) =>
    Deno.readTextFileSync(new URL(`./fixtures/junos/${name}`, import.meta.url));
  const sources = JSON.parse(read('observer-sources.json'));
  assert(sources.monitoring.fixture === 'official-monitoring-fixture.xml');
  assert(sources.configurationXnm.fixture === 'official-configuration-xnm-fixture.xml');
  // The official sample locks the candidate by session 0: parsed, and never accepted as our session.
  assertEquals(lockOwner(parseXml(bytes(read(sources.monitoring.fixture)))), '0');
  assert(
    (await configDigest(parseXml(bytes(read(sources.configurationXnm.fixture))))).length === 64,
  );
});

Deno.test('armObserved is true only after the pending commit was read back as ours', async () => {
  // Verification failure comes after the pending observation: armed.
  const m = new Mock();
  const o = options();
  o.hooks.verify = () => Promise.resolve(false);
  const failed = await change(m, o);
  assertEquals([failed.state, failed.code, failed.armObserved], [
    'rollback_pending',
    'VERIFY_FAILED',
    true,
  ]);
  // The commit was sent but the read-back did not prove it: unknown, never armed.
  const n = new Mock();
  const p = options();
  p.hooks.observe = (_nc, phase) =>
    Promise.resolve({
      lockHeld: true,
      pending: phase === 'pending' ? 'none' : phase === 'before-confirm' ? 'ours' : 'none',
      baselineRestored: false,
    });
  const unseen = await change(n, p);
  assertEquals([unseen.state, unseen.code, unseen.armObserved], [
    'rollback_pending',
    'COMMIT_OWNERSHIP_UNKNOWN',
    false,
  ]);
  assert(!n.calls.includes('<commit/>'));
});

Deno.test('hook budgets: a slow verification needs its own budget, never beyond the commit deadline', async () => {
  const slow = async () => {
    await new Promise((r) => setTimeout(r, 150));
    return true;
  };
  const tight = options({ requestTimeoutMs: 50 });
  tight.hooks.verify = slow;
  assertEquals((await change(new Mock(), tight)).code, 'TIMEOUT');
  const budget = options({ requestTimeoutMs: 50, hookTimeoutMs: { verify: 2000 } });
  budget.hooks.verify = slow;
  assertEquals((await change(new Mock(), budget)).state, 'confirmed');
  // The per-hook budget is still capped by the confirmed-commit deadline minus its margin.
  let now = 0;
  const capped = options({
    requestTimeoutMs: 50,
    hookTimeoutMs: { verify: 2000 },
    now: () => now,
  });
  capped.hooks.verify = async () => {
    now = 119000;
    await new Promise((r) => setTimeout(r, 150));
    return true;
  };
  const r = await change(new Mock(), capped);
  assert(r.state === 'rollback_pending' && !(r.code === 'CONFIRMED'));
});
