import { parseAssignment } from '../src/controller/contract.ts';
import {
  type Capture,
  type KeyStore,
  MgmtVpn,
  type MgmtVpnApi,
  parseAddresses,
  parseMgmtVpn,
  parsePeers,
  renderMgmtVpnApply,
} from '../src/controller/mgmt_vpn.ts';
import { buildDenylist } from '../src/controller/denylist.ts';
import {
  MgmtVpnUnavailable,
  renderHostNft,
  renderMgmtNetNft,
  renderMgmtSessionElement,
  type Runner,
  sessionNetwork,
  SessionNetworks,
} from '../src/controller/netns.ts';
import { assert, assertEquals, assertRejects, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';

const UUID = '0b793486-b265-4564-9bfd-df227704d8f9';
const HUB = '5d1c1c1e-2b1e-4a53-8f3a-6a4f9c0a1b22';
const HUB_KEY = 'A'.repeat(43) + '=';
const GW_PRIV = 'B'.repeat(43) + '=';
const GW_PUB = 'C'.repeat(43) + '=';

const MGMT_ASSIGNMENT = {
  ...ASSIGNMENT,
  path: 'mgmt_vpn',
  transport: 'mgmt_vpn',
  mgmtVpn: { hubUUID: HUB, source: '10.99.0.5' },
  target: { address: '10.98.1.20', port: 22 },
};

const hubAnswer = (sources: string[], extra: Record<string, unknown> = {}) => ({
  hub: {
    uuid: HUB,
    endpoint: 'hub.example.net:51820',
    publicKey: HUB_KEY,
    mgmtNet: '10.98.0.0/16',
    gatewayNet: '10.98.200.0/24',
    ...extra,
  },
  sources,
});

Deno.test('contract: mgmt_vpn assignment', () => {
  const a = parseAssignment(MGMT_ASSIGNMENT);
  assertEquals([a.path, a.transport], ['mgmt_vpn', 'mgmt_vpn']);
  assertEquals(a.mgmtVpn, { hubUUID: HUB, source: '10.99.0.5' });
  assertEquals(parseAssignment(ASSIGNMENT).mgmtVpn, null);
  // path and transport must agree
  assertThrows(
    () => parseAssignment({ ...MGMT_ASSIGNMENT, transport: 'direct' }),
    /path_unsupported/,
  );
  assertThrows(() => parseAssignment({ ...MGMT_ASSIGNMENT, path: 'public' }), /path_unsupported/);
  assertThrows(
    () => parseAssignment({ ...ASSIGNMENT, transport: 'mgmt_vpn' }),
    /path_unsupported/,
  );
  // source and hub
  for (
    const source of [undefined, '', 'host.example', '10.99.0.5/32', '2001:db8::1', '010.1.1.1']
  ) {
    assertThrows(
      () => parseAssignment({ ...MGMT_ASSIGNMENT, mgmtVpn: { hubUUID: HUB, source } }),
      /source/,
    );
  }
  assertThrows(
    () =>
      parseAssignment({ ...MGMT_ASSIGNMENT, mgmtVpn: { hubUUID: 'nope', source: '10.99.0.5' } }),
    /hubUUID/,
  );
  assertThrows(() => parseAssignment({ ...MGMT_ASSIGNMENT, mgmtVpn: null }), /hubUUID/);
  assertThrows(
    () => parseAssignment({ ...MGMT_ASSIGNMENT, target: { address: '2001:db8::1', port: 22 } }),
    /target address/,
  );
});

Deno.test('mgmt vpn: API answer validation', () => {
  assertEquals(parseMgmtVpn({ hub: null }), null);
  const ok = parseMgmtVpn(hubAnswer(['10.98.200.9', '10.98.200.2', '10.98.200.9']))!;
  assertEquals(ok.sources, ['10.98.200.2', '10.98.200.9']);
  const bad: [Record<string, unknown>, string[]][] = [
    [{ uuid: 'x' }, []],
    [{ endpoint: 'hub.example.net' }, []],
    [{ endpoint: 'hub.example.net:0' }, []],
    [{ endpoint: '-bad.example:51820' }, []],
    [{ endpoint: 'a b:1' }, []],
    [{ publicKey: 'short' }, []],
    [{ mgmtNet: '0.0.0.0/0' }, []],
    [{ mgmtNet: '10.98.0.1/16' }, []],
    [{ mgmtNet: '2001:db8::/32' }, []],
    [{ gatewayNet: '10.77.0.0/24' }, []],
    [{ gatewayNet: '10.0.0.0/8' }, []],
    [{}, ['10.77.0.5']],
    [{}, ['not-an-ip']],
    [{}, ['10.98.200.0/32']],
  ];
  for (const [extra, sources] of bad) {
    assertThrows(() => parseMgmtVpn(hubAnswer(sources, extra)), undefined);
  }
  assertEquals(
    parseMgmtVpn(hubAnswer([], { endpoint: '192.0.2.4:51820' }))!.hub.endpoint,
    '192.0.2.4:51820',
  );
  assertEquals(
    parseMgmtVpn(hubAnswer([], { endpoint: '[2001:db8::1]:51820' }))!.hub.endpoint,
    '[2001:db8::1]:51820',
  );
});

Deno.test('mgmt vpn: renderers produce the wg/ip argv', () => {
  const desired = parseMgmtVpn(hubAnswer(['10.98.200.2', '10.98.200.3']))!;
  const argv = renderMgmtVpnApply(desired, {
    exists: false,
    addresses: [],
    peers: [],
  }, '/k').map((a) => a.join(' '));
  assertEquals(argv, [
    'ip link add mnsagw-mgmt type wireguard',
    `wg set mnsagw-mgmt private-key /k peer ${HUB_KEY} endpoint hub.example.net:51820 allowed-ips 10.98.0.0/16 persistent-keepalive 25`,
    'ip link set dev mnsagw-mgmt mtu 1380',
    'ip addr add 10.98.200.2/32 dev mnsagw-mgmt',
    'ip addr add 10.98.200.3/32 dev mnsagw-mgmt',
    'ip link set dev mnsagw-mgmt up',
    'ip route replace 10.98.0.0/16 dev mnsagw-mgmt',
  ]);
  const diff = renderMgmtVpnApply(desired, {
    exists: true,
    addresses: ['10.98.200.2/32', '10.98.200.77/32'],
    peers: [HUB_KEY, 'D'.repeat(43) + '='],
  }, '/k').map((a) => a.join(' '));
  assert(!diff.some((c) => c.startsWith('ip link add')));
  assert(diff.includes(`wg set mnsagw-mgmt peer ${'D'.repeat(43)}= remove`));
  assert(diff.includes('ip addr del 10.98.200.77/32 dev mnsagw-mgmt'));
  assert(diff.includes('ip addr add 10.98.200.3/32 dev mnsagw-mgmt'));
  assert(!diff.includes('ip addr add 10.98.200.2/32 dev mnsagw-mgmt'));
  assertEquals(
    parseAddresses(
      '7: mnsagw-mgmt    inet 10.98.200.2/32 scope global mnsagw-mgmt\\ valid_lft forever\n',
    ),
    ['10.98.200.2/32'],
  );
  assertEquals(parsePeers(`${HUB_KEY}\ngarbage\n`), [HUB_KEY]);
});

Deno.test('mgmt vpn: host nft sets, accept before the denylist, snat map, no masquerade', () => {
  const nft = renderHostNft({
    denylist: buildDenylist({ environment: 'production' }),
    edgeSources: [],
    listenPort: 7443,
    mgmtNet: '10.98.0.0/16',
  });
  const lines = nft.split('\n').map((l) => l.trim());
  assert(
    nft.includes(
      'set mgmtnet4 { type ipv4_addr; flags interval; auto-merge; elements = { 10.98.0.0/16 }; }',
    ),
  );
  assert(nft.includes('set mgmtsessions4 { type ifname . ipv4_addr . inet_service; }'));
  assert(nft.includes('map mgmtsnat4 { type ifname : ipv4_addr; }'));
  const accept = lines.indexOf(
    'iifname . ip daddr . tcp dport @mgmtsessions4 ip daddr @mgmtnet4 oifname "mnsagw-mgmt" accept',
  );
  const drop = lines.indexOf('oifname "mnsagw-mgmt" drop');
  const deny = lines.indexOf('ip daddr @deny4 drop');
  const proto = lines.indexOf('meta l4proto != tcp drop');
  const established = lines.indexOf('ct state established,related accept');
  assert(established < proto && proto < accept && accept < drop && drop < deny, 'order');
  // direct sessions never get a mgmt element and the direct allow rule is unchanged
  assert(lines.includes('iifname . ip daddr . tcp dport @sessions4 accept'));
  const snat = lines.indexOf('oifname "mnsagw-mgmt" snat ip to iifname map @mgmtsnat4');
  const masq = lines.findIndex((l) => l.endsWith('masquerade'));
  assert(snat >= 0 && snat < masq, 'snat before masquerade');
  for (const line of lines.filter((l) => l.endsWith('masquerade'))) {
    assert(line.includes('oifname != "mnsagw-mgmt"'), line);
  }
  const empty = renderHostNft({
    denylist: buildDenylist({ environment: 'production' }),
    edgeSources: [],
    listenPort: 7443,
  });
  assert(empty.includes('set mgmtnet4 { type ipv4_addr; flags interval; auto-merge; }'));
  assertEquals(
    renderMgmtNetNft('10.98.0.0/16'),
    'flush set inet mnscloud_access_gateway mgmtnet4\nadd element inet mnscloud_access_gateway mgmtnet4 { 10.98.0.0/16 }\n',
  );
  assertEquals(renderMgmtNetNft(null), 'flush set inet mnscloud_access_gateway mgmtnet4\n');
  assertThrows(() => renderMgmtNetNft('2001:db8::/32'));
});

Deno.test('mgmt vpn: session elements go to the mgmt set and map only', async () => {
  const net = sessionNetwork(UUID, 0);
  const target = { address: '10.98.1.20', port: 22 };
  const mgmt = { hubUUID: HUB, source: '10.98.200.2' };
  assertEquals(
    renderMgmtSessionElement(net, target, mgmt, 'add'),
    'add element inet mnscloud_access_gateway mgmtsessions4 { "agwh0b793486" . 10.98.1.20 . 22 }\n' +
      'add element inet mnscloud_access_gateway mgmtsnat4 { "agwh0b793486" : 10.98.200.2 }\n',
  );
  assertEquals(
    renderMgmtSessionElement(net, target, mgmt, 'delete'),
    'delete element inet mnscloud_access_gateway mgmtsessions4 { "agwh0b793486" . 10.98.1.20 . 22 }\n' +
      'delete element inet mnscloud_access_gateway mgmtsnat4 { "agwh0b793486" }\n',
  );
  const scripts: string[] = [];
  const runner: Runner = (argv, stdin) => {
    if (argv[0] === 'nft' && stdin) scripts.push(stdin);
    return Promise.resolve({ code: 0, stderr: '' });
  };
  const gate = { require: () => Promise.resolve() };
  const networks = new SessionNetworks(runner, 4, undefined, undefined, gate);
  const made = await networks.create(UUID, target, mgmt);
  assert(scripts.some((s) => s.includes('mgmtsessions4') && !s.includes(' sessions4 ')));
  await networks.destroy(made, target, mgmt);
  assert(scripts.at(-1)!.startsWith('delete element'));
  const direct = await networks.create(UUID, { address: '203.0.113.10', port: 22 });
  assert(scripts.at(-1)!.includes(' sessions4 ') && !scripts.at(-1)!.includes('mgmt'));
  await networks.destroy(direct, { address: '203.0.113.10', port: 22 });
  // no gate / gate refusal: no netns is touched
  const calls: string[] = [];
  const spy: Runner = (argv) => {
    calls.push(argv.join(' '));
    return Promise.resolve({ code: 0, stderr: '' });
  };
  await assertRejects(
    () => new SessionNetworks(spy, 4).create(UUID, target, mgmt),
    /mgmt_vpn_unavailable/,
  );
  const refusing = {
    require: () => Promise.reject(new MgmtVpnUnavailable()),
  };
  await assertRejects(
    () => new SessionNetworks(spy, 4, undefined, undefined, refusing).create(UUID, target, mgmt),
    /mgmt_vpn_unavailable/,
  );
  assertEquals(calls, []);
});

// --- MgmtVpn sync against a fake host and fake API -------------------------------------------

class FakeHost {
  link = false;
  addresses: string[] = [];
  peers: string[] = [];
  commands: string[] = [];
  nft: string[] = [];
  genkeys = 0;
  fail: string | null = null;
  run: Runner = (argv, stdin) => {
    const line = argv.join(' ');
    this.commands.push(line);
    if (this.fail && line.startsWith(this.fail)) {
      return Promise.resolve({ code: 1, stderr: 'boom' });
    }
    if (argv[0] === 'nft') this.nft.push(stdin ?? '');
    if (line.startsWith('ip link add')) this.link = true;
    if (line.startsWith('ip link delete')) {
      this.link = false;
      this.addresses = [];
      this.peers = [];
    }
    if (line.startsWith('ip addr add')) this.addresses.push(argv[3]);
    if (line.startsWith('ip addr del')) {
      this.addresses = this.addresses.filter((a) => a !== argv[3]);
    }
    if (line.startsWith('wg set') && argv.includes('remove')) {
      this.peers = this.peers.filter((p) => p !== argv[4]);
    } else if (line.startsWith('wg set')) this.peers = [argv[5]];
    return Promise.resolve({ code: 0, stderr: '' });
  };
  capture: Capture = (argv) => {
    const line = argv.join(' ');
    this.commands.push(line);
    const ok = (stdout = '') => Promise.resolve({ code: 0, stdout, stderr: '' });
    if (line === 'wg genkey') {
      this.genkeys++;
      return ok(GW_PRIV + '\n');
    }
    if (line === 'wg pubkey') return ok(GW_PUB + '\n');
    if (line.startsWith('ip link show')) {
      return Promise.resolve({ code: this.link ? 0 : 1, stdout: '', stderr: '' });
    }
    if (line.startsWith('ip -o -4 addr show')) {
      return ok(
        this.addresses.map((a) => `7: mnsagw-mgmt    inet ${a} scope global mnsagw-mgmt\\`).join(
          '\n',
        ),
      );
    }
    if (line.startsWith('wg show')) return ok(this.peers.join('\n'));
    return ok();
  };
}

function setup() {
  const host = new FakeHost();
  const logs: string[] = [];
  let answer: unknown = { hub: null };
  let notFound = false;
  const reported: string[] = [];
  let stored: string | null = null;
  const keys: KeyStore = {
    path: '/k',
    read: () => Promise.resolve(stored),
    create: (key) => {
      stored = key;
      return Promise.resolve();
    },
  };
  const api: MgmtVpnApi = {
    mgmtVpn: () => Promise.resolve(notFound ? { hub: null } : answer),
    mgmtVpnKey: (key) => {
      reported.push(key);
      return Promise.resolve();
    },
  };
  const vpn = new MgmtVpn({
    api,
    run: host.run,
    capture: host.capture,
    keys,
    log: (m) => logs.push(m),
  });
  return {
    host,
    logs,
    reported,
    vpn,
    set: (value: unknown) => {
      notFound = false;
      answer = value;
    },
    notFound: () => {
      notFound = true;
    },
    stored: () => stored,
  };
}

Deno.test('mgmt vpn sync: key generated once and reported once; hub, sources, removal', async () => {
  const t = setup();
  assert(await t.vpn.sync());
  assertEquals(t.host.genkeys, 1);
  assertEquals(t.reported, [GW_PUB]);
  assertEquals(t.stored(), GW_PRIV);
  assertEquals(t.host.link, false); // no hub, no interface
  t.set(hubAnswer(['10.98.200.2']));
  assert(await t.vpn.sync());
  assertEquals(t.host.genkeys, 1);
  assertEquals(t.reported.length, 1);
  assertEquals(t.host.addresses, ['10.98.200.2/32']);
  assertEquals(t.vpn.mgmtNet, '10.98.0.0/16');
  assertEquals(t.host.nft.at(-1), renderMgmtNetNft('10.98.0.0/16'));
  assert(t.host.commands.includes('ip route replace 10.98.0.0/16 dev mnsagw-mgmt'));
  // the key never appears in any argv or log
  assert(![...t.host.commands, ...t.logs].some((c) => c.includes(GW_PRIV)));
  // source added and removed
  t.set(hubAnswer(['10.98.200.3']));
  await t.vpn.sync();
  assertEquals(t.host.addresses, ['10.98.200.3/32']);
  const nftCount = t.host.nft.length;
  await t.vpn.sync();
  assertEquals(t.host.nft.length, nftCount); // unchanged range: no nft rewrite
  // hub removed: range closed first, then the interface is deleted
  t.set({ hub: null });
  await t.vpn.sync();
  assertEquals(t.host.link, false);
  assertEquals(t.vpn.mgmtNet, null);
  const flush = t.host.commands.lastIndexOf('nft -f -');
  const del = t.host.commands.lastIndexOf('ip link delete dev mnsagw-mgmt');
  assert(flush >= 0 && del > flush);
  assertEquals(t.host.nft.at(-1), renderMgmtNetNft(null));
});

Deno.test('mgmt vpn sync: 404 means no hub, failures are reported and retried', async () => {
  const t = setup();
  t.set(hubAnswer(['10.98.200.2']));
  await t.vpn.sync();
  assert(t.host.link);
  t.notFound();
  await t.vpn.sync();
  assertEquals(t.host.link, false);
  // failing command: sync returns false, error recorded, logged once, then it recovers
  t.set(hubAnswer(['10.98.200.2']));
  t.host.fail = 'ip link add';
  assertEquals(await t.vpn.sync(), false);
  assertEquals(await t.vpn.sync(), false);
  assert(t.vpn.error?.includes('ip link add'));
  assertEquals(t.logs.filter((l) => l.includes('sync failed')).length, 1);
  t.host.fail = null;
  assert(await t.vpn.sync());
  assertEquals(t.vpn.error, null);
  // malformed answer leaves the interface untouched
  t.set(hubAnswer(['192.0.2.1']));
  assertEquals(await t.vpn.sync(), false);
  assert(t.host.link);
});

Deno.test('mgmt vpn: require checks hub, range and source, syncing when the source is new', async () => {
  const t = setup();
  t.set(hubAnswer(['10.98.200.2']));
  await t.vpn.sync();
  await t.vpn.require(HUB, '10.98.1.20', '10.98.200.2');
  await assertRejects(
    () => t.vpn.require(HUB, '10.97.1.20', '10.98.200.2'),
    /mgmt_vpn_unavailable/,
  );
  await assertRejects(
    () => t.vpn.require(HUB.replace('5', '6'), '10.98.1.20', '10.98.200.2'),
    /unavailable/,
  );
  // a new source appears in the API: the assignment triggers the sync
  t.set(hubAnswer(['10.98.200.2', '10.98.200.4']));
  await t.vpn.require(HUB, '10.98.1.20', '10.98.200.4');
  assert(t.host.addresses.includes('10.98.200.4/32'));
  // unknown source: still refused
  await assertRejects(() => t.vpn.require(HUB, '10.98.1.20', '10.98.200.9'), /unavailable/);
  // no hub at all
  const none = setup();
  await assertRejects(() => none.vpn.require(HUB, '10.98.1.20', '10.98.200.2'), /unavailable/);
});
