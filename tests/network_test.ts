import { buildDenylist, checkDestination } from '../src/controller/denylist.ts';
import {
  renderHostNft,
  renderHostSessionElement,
  renderNetnsSetup,
  renderNetnsTeardown,
  renderSessionNft,
  type Runner,
  sessionNetwork,
  SessionNetworks,
} from '../src/controller/netns.ts';
import { allowNet, renderSystemdRun } from '../src/controller/sandbox.ts';
import { parseCidr } from '../src/shared/ip.ts';
import { assert, assertEquals, assertRejects, assertThrows } from './assert.ts';

const UUID = '0b793486-b265-4564-9bfd-df227704d8f9';

Deno.test('denylist: built-in special ranges and platform ranges are refused', () => {
  const list = buildDenylist({
    environment: 'production',
    denylist: ['198.51.100.0/24', '2001:db8:1::/48'],
  });
  for (
    const address of [
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '100.64.0.1',
      '127.0.0.1',
      '169.254.169.254',
      '0.0.0.0',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      'fe80::1',
      'fd00::1',
      '::ffff:10.0.0.1',
      '64:ff9b::a00:1',
      '2002:a00:1::1',
      '198.51.100.7',
    ]
  ) {
    assertEquals(checkDestination(address, list).allowed, false, address);
  }
  for (const address of ['8.8.8.8', '2606:4700:4700::1111']) {
    assertEquals(checkDestination(address, list).allowed, true, address);
  }
  assertEquals(checkDestination('not-an-ip', list).allowed, false);
  assertEquals(checkDestination('example.com', list).allowed, false);
});

Deno.test('denylist: DEV lab /32 targets only in development, never in production', () => {
  const dev = buildDenylist({ environment: 'development', labTargets: ['10.20.30.40/32'] });
  assertEquals(checkDestination('10.20.30.40', dev), { allowed: true, lab: true });
  assertEquals(checkDestination('10.20.30.41', dev).allowed, false);
  const prod = buildDenylist({ environment: 'production', labTargets: ['10.20.30.40/32'] });
  assertEquals(checkDestination('10.20.30.40', prod).allowed, false);
  assertThrows(
    () => buildDenylist({ environment: 'development', labTargets: ['10.20.30.0/24'] }),
    /single hosts/,
  );
});

Deno.test('netns: per-session addressing and interface names fit the kernel limits', () => {
  const net = sessionNetwork(UUID, 3);
  assertEquals(net.namespace, 'mnsagw-0b793486');
  assertEquals([net.hostIf.length <= 15, net.nsIf.length <= 15], [true, true]);
  assertEquals([net.host4, net.ns4], ['100.127.192.13', '100.127.192.14']);
  assertEquals([net.host6, net.ns6], ['fd6d:6e73:6177:3::1', 'fd6d:6e73:6177:3::2']);
  assertThrows(() => sessionNetwork('bad', 0));
  assertThrows(() => sessionNetwork(UUID, 999999));
  const setup = renderNetnsSetup(net).map((a) => a.join(' '));
  assertEquals(setup[0], 'ip netns add mnsagw-0b793486');
  assert(setup.includes('ip netns exec mnsagw-0b793486 ip route add default via 100.127.192.13'));
  assertEquals(renderNetnsTeardown(net)[0].join(' '), 'ip netns delete mnsagw-0b793486');
});

Deno.test('netns: session table allows output only to the device IP:port, no DNS', () => {
  const nft = renderSessionNft({ address: '203.0.113.10', port: 22 });
  assert(nft.includes('policy drop;'));
  assert(nft.includes('ip daddr 203.0.113.10 tcp dport 22 ct state new accept'));
  assert(!/dport 53|udp/.test(nft));
  const v6 = renderSessionNft({ address: '2001:db8::5', port: 8729 });
  assert(v6.includes('ip6 daddr 2001:db8::5 tcp dport 8729 ct state new accept'));
  assertThrows(() => renderSessionNft({ address: 'example.com', port: 22 }));
  assertThrows(() => renderSessionNft({ address: '203.0.113.10', port: 0 }));
});

Deno.test('netns: host table drops the denylist before the per-session allow set', () => {
  const nft = renderHostNft({
    denylist: buildDenylist({
      environment: 'development',
      denylist: ['198.51.100.0/24'],
      labTargets: ['10.9.9.9/32'],
    }),
    edgeSources: [parseCidr('10.0.0.5/32')!],
    listenPort: 7443,
  });
  const lines = nft.split('\n').map((l) => l.trim());
  const deny = lines.indexOf('ip daddr @deny4 drop');
  const allow = lines.indexOf('iifname . ip daddr . tcp dport @sessions4 accept');
  const lab = lines.indexOf('iifname . ip daddr . tcp dport @sessions4 ip daddr @lab4 accept');
  assert(lab >= 0 && deny > lab && allow > deny, 'order: lab, deny, allow');
  assert(
    nft.includes('169.254.0.0/16') && nft.includes('198.51.100.0/24') &&
      nft.includes('10.9.9.9/32'),
  );
  assert(
    nft.includes('tcp dport 7443 ip saddr @edge4 accept') && nft.includes('tcp dport 7443 drop'),
  );
  assert(nft.includes('type filter hook forward priority filter - 5; policy drop;'));
  assert(
    nft.startsWith(
      'table inet mnscloud_access_gateway {}\ndelete table inet mnscloud_access_gateway\n',
    ),
  );
  const net = sessionNetwork(UUID, 0);
  assertEquals(
    renderHostSessionElement(net, { address: '203.0.113.10', port: 22 }, 'add'),
    'add element inet mnscloud_access_gateway sessions4 { "agwh0b793486" . 203.0.113.10 . 22 }\n',
  );
});

Deno.test('netns: a failed step tears the namespace down and frees the slot', async () => {
  const calls: string[] = [];
  let fail = true;
  const runner: Runner = (argv) => {
    calls.push(argv.join(' '));
    return Promise.resolve({ code: fail && argv.includes('veth') ? 1 : 0, stderr: '' });
  };
  const networks = new SessionNetworks(runner, 1);
  await assertRejects(() => networks.create(UUID, { address: '203.0.113.10', port: 22 }));
  assert(calls.some((c) => c === 'ip netns delete mnsagw-0b793486'));
  fail = false;
  const net = await networks.create(UUID, { address: '203.0.113.10', port: 22 });
  assertEquals(net.index, 0);
  await assertRejects(
    () =>
      networks.create('1b793486-b265-4564-9bfd-df227704d8f9', {
        address: '203.0.113.11',
        port: 22,
      }),
    /slot/,
  );
  await networks.destroy(net, { address: '203.0.113.10', port: 22 });
});

Deno.test('sandbox: systemd-run properties of the worker', () => {
  const net = sessionNetwork(UUID, 0);
  const argv = renderSystemdRun(
    net,
    { address: '203.0.113.10', port: 22 },
    '/opt/mnscloud/mnscloud-access-gateway',
    {
      memoryMaxMB: 256,
      cpuQuotaPercent: 50,
      tasksMax: 64,
      maxSessionSeconds: 3600,
    },
  );
  const props = argv.flatMap((a, i) => (argv[i - 1] === '-p' ? [a] : []));
  for (
    const expected of [
      'NetworkNamespacePath=/run/netns/mnsagw-0b793486',
      'DynamicUser=yes',
      'MemoryMax=256M',
      'CPUQuota=50%',
      'RuntimeMaxSec=3630',
      'NoNewPrivileges=yes',
      'ProtectSystem=strict',
      'CapabilityBoundingSet=',
      'AmbientCapabilities=',
      'RestrictAddressFamilies=AF_INET',
      'IPAddressAllow=203.0.113.10',
      'IPAddressDeny=any',
    ]
  ) {
    assert(props.includes(expected), expected);
  }
  assert(
    argv.includes('--pipe') && argv.includes('--wait') &&
      argv.includes('--unit=mnscloud-access-gateway-session-0b793486'),
  );
  assert(argv.includes('--allow-net=203.0.113.10:22'));
  assert(
    !argv.some((a) =>
      a === '--allow-all' || a.startsWith('--allow-run') || a.startsWith('--allow-env') ||
      a.startsWith('--allow-write')
    ),
  );
  assertEquals(allowNet({ address: '2001:db8::5', port: 22 }), '[2001:db8::5]:22');
});
