// Connector side: destination checks, OPEN handling, remote configuration, install scripts.

import { parseLocalConfig, parseRemoteConfig, relayUrlFor } from '../src/connector/config.ts';
import { handleOpen } from '../src/connector/open.ts';
import { backoffMs } from '../src/connector/tunnel.ts';
import {
  checkConnectorDestination,
  type DestinationPolicy,
  ownAddressesOf,
  parseAllowedCidrs,
  reportedAddresses,
} from '../src/shared/destination.ts';
import { decodeFrame, encodeFrame, FrameType, Mux, type OpenSpec } from '../src/shared/tunnel.ts';
import { assert, assertEquals, assertMatch } from './assert.ts';

const UUID = '0b793486-b265-4564-9bfd-df227704d8f9';
const policy: DestinationPolicy = {
  allowedCidrs: [],
  ownAddresses: ['192.168.1.10', '192.168.1.255'],
};

Deno.test('destination: tenant private ranges allowed; loopback, link-local, multicast, unspecified, broadcast, own refused', () => {
  for (const host of ['10.20.30.40', '192.168.1.20', '172.16.5.5', '100.64.1.1', '198.51.100.7']) {
    assertEquals(checkConnectorDestination(host, 22, policy), null, host);
  }
  for (
    const host of [
      '127.0.0.1',
      '127.9.9.9',
      '169.254.169.254',
      '169.254.1.1',
      '224.0.0.1',
      '239.255.255.250',
      '0.0.0.0',
      '255.255.255.255',
      '240.0.0.1',
      '::1',
      '::',
      'fe80::1',
      'ff02::1',
      '::ffff:10.0.0.1',
    ]
  ) {
    assertEquals(checkConnectorDestination(host, 22, policy), 'destination_refused', host);
  }
  assertEquals(checkConnectorDestination('192.168.1.10', 22, policy), 'destination_refused');
  assertEquals(checkConnectorDestination('192.168.1.255', 22, policy), 'destination_refused');
  assertEquals(checkConnectorDestination('fd00::5', 22, policy), null);
  assertEquals(checkConnectorDestination('router.example.com', 22, policy), 'invalid_address');
  assertEquals(checkConnectorDestination('10.0.0.1', 0, policy), 'invalid_port');
  assertEquals(checkConnectorDestination('10.0.0.1', 70000, policy), 'invalid_port');
  assertEquals(checkConnectorDestination('10.0.0.1', 23, policy), 'protocol_refused');
  assertEquals(checkConnectorDestination('10.0.0.1', 8728, policy), 'protocol_refused');
  assertEquals(checkConnectorDestination('10.0.0.1', 8729, policy), null);
});

Deno.test('destination: allowedCidrs narrow the destinations', () => {
  const allowed = parseAllowedCidrs(['10.20.0.0/16', 'fd00::/8'])!;
  const narrow = { allowedCidrs: allowed, ownAddresses: [] };
  assertEquals(checkConnectorDestination('10.20.30.40', 22, narrow), null);
  assertEquals(checkConnectorDestination('fd00::7', 22, narrow), null);
  assertEquals(checkConnectorDestination('10.21.0.1', 22, narrow), 'not_allowed');
  assertEquals(checkConnectorDestination('192.168.1.1', 22, narrow), 'not_allowed');
  // The always-refused set wins over any allowed network.
  const wide = { allowedCidrs: parseAllowedCidrs(['0.0.0.0/0'])!, ownAddresses: [] };
  assertEquals(checkConnectorDestination('127.0.0.1', 22, wide), 'destination_refused');
  assertEquals(parseAllowedCidrs(['nope']), null);
  assertEquals(parseAllowedCidrs(new Array(65).fill('10.0.0.0/8')), null);
  assertEquals(parseAllowedCidrs(undefined), []);
});

Deno.test('destination: own addresses include directed broadcast; reported ones skip link-local', () => {
  const interfaces = [
    { address: '192.168.1.10', netmask: '255.255.255.0', family: 'IPv4', cidr: '192.168.1.10/24' },
    { address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', cidr: '127.0.0.1/8' },
    { address: 'fe80::1', family: 'IPv6', cidr: 'fe80::1/64' },
    { address: 'fd00::9', family: 'IPv6', cidr: 'fd00::9/64' },
  ];
  const own = ownAddressesOf(interfaces);
  assert(own.includes('192.168.1.10') && own.includes('192.168.1.255') && own.includes('fd00::9'));
  assertEquals(reportedAddresses(interfaces), ['192.168.1.10', 'fd00::9']);
});

class Harness {
  sent: { type: number; stream: number; payload: Uint8Array }[] = [];
  mux = new Mux({
    role: 'connector',
    send: (b) => this.sent.push(decodeFrame(b)),
    onFatal: () => {},
    maxStreams: 4,
  });
  accepted: string[] = [];
  connected: string[] = [];
  logs: string[] = [];
  open(
    spec: Partial<OpenSpec>,
    deps: { accept?: boolean | 'error'; policy?: DestinationPolicy } = {},
  ) {
    const full = { connectionUuid: UUID, host: '10.20.30.40', port: 22, ...spec };
    return handleOpen(this.mux, 1, full, {
      policy: () => deps.policy ?? policy,
      accept: (uuid, host, port) => {
        this.accepted.push(`${uuid} ${host}:${port}`);
        if (deps.accept === 'error') {
          return Promise.reject(Object.assign(new Error('x'), { status: 403 }));
        }
        return Promise.resolve(deps.accept !== false);
      },
      connect: (host, port) => {
        this.connected.push(`${host}:${port}`);
        return Promise.reject(new Error('refused'));
      },
      log: (m) => this.logs.push(m),
    });
  }
  last() {
    const frame = this.sent.at(-1)!;
    return [frame.type, new TextDecoder().decode(frame.payload)] as const;
  }
}

Deno.test('open: refusals answer OPEN_FAIL and never ask the API or dial', async () => {
  for (
    const [spec, code] of [
      [{ host: '127.0.0.1' }, 'destination_refused'],
      [{ host: '169.254.169.254' }, 'destination_refused'],
      [{ host: '224.0.0.1' }, 'destination_refused'],
      [{ host: '192.168.1.10' }, 'destination_refused'],
      [{ port: 23 }, 'protocol_refused'],
      [{ host: 'router.example.com' }, 'invalid_address'],
      [{ connectionUuid: 'not-a-uuid' }, 'invalid_open'],
    ] as [Partial<OpenSpec>, string][]
  ) {
    const h = new Harness();
    await h.open(spec);
    const [type, payload] = h.last();
    assertEquals(type, FrameType.OPEN_FAIL);
    assertMatch(payload, new RegExp(code));
    assertEquals([h.accepted.length, h.connected.length], [0, 0]);
  }
  const narrow = new Harness();
  await narrow.open({}, {
    policy: { allowedCidrs: parseAllowedCidrs(['172.16.0.0/12'])!, ownAddresses: [] },
  });
  assertMatch(narrow.last()[1], /not_allowed/);
  assertEquals(narrow.accepted.length, 0);
});

Deno.test('open: the API must confirm the connection before the dial', async () => {
  const denied = new Harness();
  await denied.open({}, { accept: false });
  assertMatch(denied.last()[1], /api_refused/);
  assertEquals(denied.connected, []);
  const forbidden = new Harness();
  await forbidden.open({}, { accept: 'error' });
  assertMatch(forbidden.last()[1], /api_refused/);
  assertEquals(forbidden.accepted, [`${UUID} 10.20.30.40:22`]);
  assertEquals(forbidden.connected, []);
  // Confirmed, but the device does not answer: connect_failed, still no OPEN_OK.
  const down = new Harness();
  await down.open({});
  assertEquals(down.connected, ['10.20.30.40:22']);
  assertMatch(down.last()[1], /connect_failed/);
});

Deno.test('open: a confirmed connection is piped to the device', async () => {
  const echo = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  void (async () => {
    for await (const conn of echo) {
      conn.readable.pipeTo(conn.writable).catch(() => {});
    }
  })();
  const h = new Harness();
  const done = handleOpen(h.mux, 3, { connectionUuid: UUID, host: '10.20.30.40', port: 22 }, {
    policy: () => policy,
    accept: () => Promise.resolve(true),
    connect: () => Deno.connect({ hostname: '127.0.0.1', port: (echo.addr as Deno.NetAddr).port }),
    log: () => {},
  });
  await new Promise((r) => setTimeout(r, 50));
  assertEquals(h.sent.at(-1)?.type, FrameType.OPEN_OK);
  h.mux.receive(encodeFrame(FrameType.DATA, 3, new TextEncoder().encode('ping')));
  await new Promise((r) => setTimeout(r, 50));
  const data = h.sent.filter((f) => f.type === FrameType.DATA && f.stream === 3);
  assertEquals(new TextDecoder().decode(data[0].payload), 'ping');
  h.mux.receive(encodeFrame(FrameType.CLOSE, 3));
  await done;
  echo.close();
});

Deno.test('config: local file, relay URL and remote configuration are validated', () => {
  const local = parseLocalConfig(JSON.stringify({
    apiUrl: 'https://api.example.com',
    connectorUuid: UUID,
    keyFile: '/etc/mnscloud-access-connector/key.pkcs8',
  }));
  assertEquals(local.apiUrl, 'https://api.example.com/api/v1');
  for (const bad of [{ keyFile: '/etc/../x' }, { connectorUuid: 'x' }, { apiUrl: 'http://a' }]) {
    let threw = false;
    try {
      parseLocalConfig(JSON.stringify({
        apiUrl: 'https://api.example.com',
        connectorUuid: UUID,
        keyFile: '/etc/k',
        ...bad,
      }));
    } catch {
      threw = true;
    }
    assert(threw);
  }
  const api = 'https://api.example.com/api/v1';
  const url = 'wss://gw.example.com/access-gateway/gw-dev1/connector';
  assertEquals(relayUrlFor('gw-dev1', url, undefined, api), url);
  assertEquals(
    relayUrlFor('gw-dev1', undefined, '/access-gateway/gw-dev1/connector', api),
    'wss://api.example.com/access-gateway/gw-dev1/connector',
  );
  for (
    const bad of [
      'ws://gw.example.com/access-gateway/gw-dev1/connector',
      'wss://u:p@gw.example.com/access-gateway/gw-dev1/connector',
      'wss://gw.example.com/access-gateway/gw-dev1/connector?x=1',
      'wss://gw.example.com/access-gateway/other/connector',
      'wss://gw.example.com/ws',
    ]
  ) assertEquals(relayUrlFor('gw-dev1', bad, undefined, api), null, bad);
  const remote = parseRemoteConfig({
    allowedCidrs: ['10.0.0.0/8'],
    gateway: { key: 'gw-dev1', relayUrl: url },
    release: { tag: 'v0.1.4', commit: 'a'.repeat(40) },
  }, api);
  assertEquals(remote?.gateway, { key: 'gw-dev1', relayUrl: url });
  assertEquals(remote?.allowedCidrs.length, 1);
  assertEquals(parseRemoteConfig({ allowedCidrs: [], gateway: null }, api)?.gateway, null);
  assertEquals(parseRemoteConfig({ allowedCidrs: ['bad'] }, api), null);
  assertEquals(parseRemoteConfig({ release: { tag: 'main', commit: 'a'.repeat(40) } }, api), null);
  assertEquals(parseRemoteConfig({ gateway: { key: 'GW!', relayUrl: url } }, api), null);
});

Deno.test('tunnel: reconnect backoff doubles to a 60 s cap with jitter', () => {
  const none = () => 0.5;
  assertEquals([1, 2, 3, 4, 7, 20].map((n) => backoffMs(n, none)), [
    1000,
    2000,
    4000,
    8000,
    60000,
    60000,
  ]);
  assert(backoffMs(3, () => 0) < backoffMs(3, () => 1));
});

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

Deno.test('install: scripts pass shellcheck, take the token from the environment only', async () => {
  const scripts = [
    'scripts/install-connector.sh',
    'scripts/update-connector.sh',
    'scripts/uninstall-connector.sh',
    'scripts/lib/connector.sh',
  ];
  try {
    const result = await new Deno.Command('shellcheck', {
      args: ['-x', ...scripts],
      cwd: ROOT,
      stdout: 'piped',
      stderr: 'piped',
    }).output();
    assertEquals(new TextDecoder().decode(result.stdout), '');
    assertEquals(result.code, 0);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  const install = Deno.readTextFileSync(`${ROOT}/scripts/install-connector.sh`);
  assertMatch(install, /MNSCLOUD_CONNECTOR_TOKEN/);
  assertMatch(install, /printf '%s' "\$TOKEN" \| /); // stdin, never an argument
  assert(!/--token/.test(install));
  assertMatch(Deno.readTextFileSync(`${ROOT}/scripts/lib/connector.sh`), /NoNewPrivileges=yes/);
  assertMatch(Deno.readTextFileSync(`${ROOT}/scripts/lib/connector.sh`), /ProtectSystem=strict/);
  assertMatch(
    Deno.readTextFileSync(`${ROOT}/scripts/lib/connector.sh`),
    /CapabilityBoundingSet=\n/,
  );
});
