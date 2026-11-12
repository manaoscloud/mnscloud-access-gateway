// Regression tests for the review findings of the connector (tunnel, hub, bridge, scripts).

import { tempDir } from './tmp.ts';
import { handleOpen } from '../src/connector/open.ts';
import { startBridge } from '../src/controller/bridge.ts';
import {
  AttachRefused,
  ConnectorHub,
  type HubSocket,
  sourceOf,
} from '../src/controller/connector_hub.ts';
import { renderConnectorSystemdRun, unixSocketNeedsNet } from '../src/controller/sandbox.ts';
import { openFailure } from '../src/controller/session.ts';
import {
  importPrivateKey,
  pkcs8FromSeed,
  signText,
  tunnelSigningString,
} from '../src/shared/connector_auth.ts';
import {
  encodeFrame,
  encodeOpen,
  FrameType,
  MAX_BUFFERED_BYTES,
  MAX_QUEUED_CHUNKS,
  Mux,
  OpenError,
  type OpenSpec,
  type TunnelStream,
} from '../src/shared/tunnel.ts';
import { validateInit } from '../src/worker/worker.ts';
import { assert, assertEquals, assertMatch } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const SPEC: OpenSpec = {
  connectionUuid: '0b793486-b265-4564-9bfd-df227704d8f9',
  host: '10.20.30.40',
  port: 22,
};
const settle = (ms = 30) => new Promise((r) => setTimeout(r, ms));

function gatewayMux(extra: Partial<ConstructorParameters<typeof Mux>[0]> = {}) {
  const fatal: string[] = [];
  const sent: number[] = [];
  const mux = new Mux({
    role: 'gateway',
    send: (b) => sent.push(b[0]),
    onFatal: (r) => fatal.push(r),
    maxStreams: 4,
    ...extra,
  });
  return { mux, fatal, sent };
}

async function openedStream(mux: Mux) {
  const p = mux.open(SPEC, 1000);
  mux.receive(encodeFrame(FrameType.OPEN_OK, 1));
  return await p;
}

Deno.test('finding 1: empty DATA frames and queue growth are protocol violations', async () => {
  const a = gatewayMux();
  await openedStream(a.mux);
  a.mux.receive(encodeFrame(FrameType.DATA, 1));
  assertEquals(a.fatal, ['empty data']);
  const b = gatewayMux();
  await openedStream(b.mux);
  for (let i = 0; i < MAX_QUEUED_CHUNKS; i++) {
    b.mux.receive(encodeFrame(FrameType.DATA, 1, Uint8Array.of(1)));
  }
  assertEquals(b.fatal, []);
  b.mux.receive(encodeFrame(FrameType.DATA, 1, Uint8Array.of(1)));
  assertEquals(b.fatal, ['queue overflow']);
});

Deno.test('finding 4: a timed-out OPEN frees its slot and is counted once', async () => {
  const { mux } = gatewayMux();
  for (let i = 0; i < 4; i++) {
    const error = await mux.open(SPEC, 5).then(() => null, (e) => e);
    assertEquals((error as OpenError).code, 'open_timeout');
  }
  assertEquals([mux.streams.size, mux.streamCount], [0, 0]);
  // A pending OPEN counts once toward the limit.
  const pending = mux.open(SPEC, 1000);
  assertEquals(mux.streamCount, 1);
  mux.close();
  await pending.catch(() => {});
});

Deno.test('finding 5: PING reflection is rate limited and a non-reading peer ends the tunnel', () => {
  let now = 1_000_000;
  const { mux, sent } = gatewayMux({ now: () => now });
  for (let i = 0; i < 50; i++) mux.receive(encodeFrame(FrameType.PING, 0));
  assertEquals(sent.filter((t) => t === FrameType.PONG).length, 1);
  now += 2500;
  mux.receive(encodeFrame(FrameType.PING, 0));
  assertEquals(sent.filter((t) => t === FrameType.PONG).length, 2);
  let buffered = 0;
  const b = gatewayMux({ bufferedAmount: () => buffered });
  b.mux.sendFrame(FrameType.PING, 0);
  assertEquals(b.fatal, []);
  buffered = MAX_BUFFERED_BYTES + 1;
  b.mux.sendFrame(FrameType.PING, 0);
  assertEquals(b.fatal, ['backpressure']);
});

class FakeConn {
  closed = false;
  close() {
    this.closed = true;
  }
}

function connectorMux(maxStreams = 4) {
  const sent: { type: number; stream: number }[] = [];
  const fatal: string[] = [];
  const mux = new Mux({
    role: 'connector',
    send: (b) =>
      sent.push({ type: b[0], stream: new DataView(b.buffer, b.byteOffset).getUint32(1) }),
    onFatal: (r) => fatal.push(r),
    maxStreams,
  });
  return { mux, sent, fatal };
}

const open = (mux: Mux, id: number) =>
  mux.receive(encodeFrame(FrameType.OPEN, id, encodeOpen(SPEC)));

Deno.test('finding 9: CLOSE of an in-flight OPEN aborts accept and sends no reply', async () => {
  const { mux, sent } = connectorMux();
  open(mux, 1);
  let aborted = false;
  const done = handleOpen(mux, 1, SPEC, {
    policy: () => ({ allowedCidrs: [] }),
    accept: (_u, _h, _p, signal) =>
      new Promise((_, reject) => {
        signal.addEventListener('abort', () => {
          aborted = true;
          reject(new Error('aborted'));
        });
      }),
    connect: () => Promise.reject(new Error('must not dial')),
    log: () => {},
  });
  await settle(10);
  mux.receive(encodeFrame(FrameType.CLOSE, 1));
  await done;
  assert(aborted);
  assertEquals(sent, []);
});

Deno.test('finding 9: gateway gives up while the connector dials: the device connection is closed', async () => {
  const { mux, sent } = connectorMux();
  open(mux, 1);
  const conn = new FakeConn();
  let release!: () => void;
  const done = handleOpen(mux, 1, SPEC, {
    policy: () => ({ allowedCidrs: [] }),
    accept: () => Promise.resolve(true),
    connect: () =>
      new Promise((resolve) => (release = () => resolve(conn as unknown as Deno.Conn))),
    log: () => {},
  });
  await settle(10);
  mux.receive(encodeFrame(FrameType.CLOSE, 1));
  release();
  await done;
  assert(conn.closed, 'device connection closed');
  assertEquals(sent, []);
});

Deno.test('finding 9: tunnel death mid-accept cancels the open', async () => {
  const { mux, sent } = connectorMux();
  open(mux, 1);
  const done = handleOpen(mux, 1, SPEC, {
    policy: () => ({ allowedCidrs: [] }),
    accept: (_u, _h, _p, signal) =>
      new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('x')))),
    connect: () => Promise.reject(new Error('must not dial')),
    log: () => {},
  });
  await settle(10);
  mux.close();
  await done;
  assertEquals(sent, []);
});

Deno.test('finding 9: duplicate in-flight ids end the tunnel; in-flight opens count against the limit', () => {
  const a = connectorMux();
  open(a.mux, 5);
  open(a.mux, 5);
  assertEquals(a.fatal, ['bad stream id']);
  const b = connectorMux(1);
  open(b.mux, 1);
  open(b.mux, 2);
  assertEquals(b.sent.map((f) => [f.type, f.stream]), [[FrameType.OPEN_FAIL, 2]]);
});

// ---- hub

const PUBLIC_KEY = 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg';
const FINGERPRINT = 'SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=';
const CONNECTOR = '11111111-2222-4333-8444-555555555555';

class FakeSocket implements HubSocket {
  readyState = 1;
  binaryType = 'blob';
  closed: [number, string] | null = null;
  sent: (string | Uint8Array)[] = [];
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  send(data: string | Uint8Array) {
    this.sent.push(data);
  }
  close(code = 1000, reason = '') {
    if (this.closed) return;
    this.closed = [code, reason];
    queueMicrotask(() => this.onclose?.({} as CloseEvent));
  }
  challenge(): string {
    return JSON.parse(this.sent.find((s) => typeof s === 'string') as string).challenge;
  }
}

async function hello(socket: FakeSocket, uuid = CONNECTOR) {
  const key = await importPrivateKey(pkcs8FromSeed(Uint8Array.from({ length: 32 }, (_, i) => i)));
  socket.onmessage?.({
    data: JSON.stringify({
      t: 'hello',
      connectorUuid: uuid,
      signature: await signText(key, tunnelSigningString('gw-dev1', socket.challenge())),
    }),
  } as MessageEvent);
}

function hubWith(
  api: Partial<ConstructorParameters<typeof ConnectorHub>[0]['api']> = {},
  recheckMs = 20,
) {
  const calls: string[] = [];
  const hub = new ConnectorHub({
    gatewayKey: 'gw-dev1',
    api: {
      connector: () => Promise.resolve({ publicKey: PUBLIC_KEY }),
      connectorAttach: (u) => {
        calls.push(`attach:${u}`);
        return Promise.resolve();
      },
      connectorDetach: (u) => {
        calls.push(`detach:${u}`);
        return Promise.resolve();
      },
      ...api,
    },
    maxStreams: () => 4,
    log: () => {},
    recheckMs,
  });
  return { hub, calls };
}

Deno.test('finding 3: an attached tunnel is closed when its key is disabled or changed', async () => {
  for (const next of [null, { publicKey: 'B6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg' }]) {
    let current: { publicKey: string } | null = { publicKey: PUBLIC_KEY };
    const { hub, calls } = hubWith({ connector: () => Promise.resolve(current) });
    const socket = new FakeSocket();
    hub.attach(socket);
    await hello(socket);
    await settle();
    assert(hub.has(CONNECTOR));
    current = next;
    await settle(80);
    assertEquals(socket.closed?.[0], 4401);
    assert(!hub.has(CONNECTOR));
    assertEquals(calls.at(-1), `detach:${CONNECTOR}`);
  }
  // A transient API error keeps the tunnel.
  let fail = false;
  const { hub } = hubWith({
    connector: () =>
      fail ? Promise.reject(new Error('down')) : Promise.resolve({ publicKey: PUBLIC_KEY }),
  });
  const socket = new FakeSocket();
  hub.attach(socket);
  await hello(socket);
  await settle();
  fail = true;
  await settle(80);
  assertEquals(socket.closed, null);
});

Deno.test('finding 3: a stream is refused when the tunnel key is not the one the API pinned', async () => {
  const { hub } = hubWith();
  const socket = new FakeSocket();
  hub.attach(socket);
  await hello(socket);
  await settle();
  assertEquals(hub.fingerprintOf(CONNECTOR), FINGERPRINT);
  const wrong = 'SHA256:' + 'A'.repeat(43) + '=';
  const error = await hub.open(CONNECTOR, SPEC, wrong).then(() => null, (e) => e);
  assertEquals((error as OpenError).code, 'connector_key_mismatch');
  assertEquals(openFailure('connector_key_mismatch').state, 'refused');
});

Deno.test('finding 7: per-source and lookup caps, short default handshake, trusted-edge source', async () => {
  const request = (h: Record<string, string>) =>
    new Request('https://gw/x', { headers: { upgrade: 'websocket', ...h } });
  assertEquals(sourceOf(request({ 'x-real-ip': '198.51.100.7' }), '10.0.0.5'), '198.51.100.7');
  assertEquals(
    sourceOf(request({ 'x-forwarded-for': '203.0.113.9, 198.51.100.8' }), '10.0.0.5'),
    '198.51.100.8',
  );
  assertEquals(sourceOf(request({ 'x-real-ip': 'garbage' }), '10.0.0.5'), '10.0.0.5');
  const { hub } = hubWith();
  const sockets = [0, 1, 2, 3].map(() => {
    const s = new FakeSocket();
    hub.attach(s, '198.51.100.7');
    return s;
  });
  const busy = hub.handleUpgrade(request({ 'x-real-ip': '198.51.100.7' }), '10.0.0.5');
  assertEquals(busy.status, 503);
  for (const s of sockets) s.close();
  await settle();
  // Key lookups are bounded: the ninth concurrent hello is turned away without an API call.
  let lookups = 0;
  const slow = hubWith({
    connector: () => {
      lookups++;
      return new Promise(() => {});
    },
  }).hub;
  const many = Array.from({ length: 10 }, () => new FakeSocket());
  for (const [i, s] of many.entries()) {
    slow.attach(s, `198.51.100.${i + 10}`);
    await hello(s);
  }
  await settle();
  assertEquals(lookups, 8);
  assertEquals(many.filter((s) => s.closed?.[0] === 4429).length, 2);
});

Deno.test('finding 10: a stale tunnel closing never detaches the live attachment', async () => {
  let releaseAttach!: () => void;
  let slow = false;
  const { hub, calls } = hubWith({
    connectorAttach: (u) => {
      calls.push(`attach:${u}`);
      return slow ? new Promise<void>((r) => (releaseAttach = r)) : Promise.resolve();
    },
  });
  const first = new FakeSocket();
  hub.attach(first);
  await hello(first);
  await settle();
  slow = true;
  const second = new FakeSocket();
  hub.attach(second);
  await hello(second);
  await settle();
  first.close(); // the old tunnel dies while the new attach is still in flight
  await settle();
  releaseAttach();
  await settle();
  assert(hub.has(CONNECTOR));
  assertEquals(calls.filter((c) => c.startsWith('detach:')), []);
});

Deno.test('finding 11: the connector cannot choose the finish reason', () => {
  assertEquals(openFailure('totally_made_up'), {
    state: 'failed',
    reason: 'connector_open_failed',
  });
  assertEquals(openFailure('Robert); DROP'), { state: 'failed', reason: 'connector_open_failed' });
  assertEquals(openFailure('connect_timeout'), { state: 'failed', reason: 'connect_timeout' });
  assertEquals(openFailure('destination_refused'), {
    state: 'refused',
    reason: 'destination_refused',
  });
});

// ---- bridge and sandbox

class FakeStream {
  written: Uint8Array[] = [];
  closed = false;
  #waiter: ((c: Uint8Array | null) => void) | null = null;
  read() {
    return new Promise<Uint8Array | null>((resolve) => (this.#waiter = resolve));
  }
  write(b: Uint8Array) {
    this.written.push(b);
    return Promise.resolve();
  }
  close() {
    this.closed = true;
    this.#waiter?.(null);
  }
}

Deno.test('finding 2: the bridge pipes only the peer that presents the session secret', async () => {
  const dir = await tempDir('agw-bridge-');
  const stream = new FakeStream();
  const bridge = await startBridge(stream as unknown as TunnelStream, dir);
  assertMatch(bridge.secret, /^[0-9a-f]{64}$/);
  // An impostor (another session's worker) connects first with a wrong secret.
  const impostor = await Deno.connect({ transport: 'unix', path: bridge.path });
  await impostor.write(new TextEncoder().encode('0'.repeat(64) + 'stolen'));
  const buffer = new Uint8Array(16);
  assertEquals(await impostor.read(buffer), null, 'impostor is dropped');
  assertEquals(stream.written.length, 0);
  assert(!stream.closed, 'the real worker can still connect');
  const worker = await Deno.connect({ transport: 'unix', path: bridge.path });
  await worker.write(new TextEncoder().encode(bridge.secret + 'SSH-2.0-x'));
  await settle(50);
  assertEquals(new TextDecoder().decode(stream.written[0]), 'SSH-2.0-x');
  worker.close();
  await settle(50);
  assert(stream.closed);
  await Deno.remove(dir, { recursive: true });
});

Deno.test('finding 2: connector workers see a private /run with the bridge under a fixed name', () => {
  const real = '/run/mnscloud-access-gateway-bridge/0123456789abcdef0123456789abcdef.sock';
  const argv = renderConnectorSystemdRun(
    '0b793486',
    { address: '10.20.30.40', port: 22 },
    '/opt/x',
    { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64, maxSessionSeconds: 3600 },
    real,
  );
  const props = new Set(argv.flatMap((a, i) => (argv[i - 1] === '-p' ? [a] : [])));
  assert(props.has('TemporaryFileSystem=/run:ro'));
  assert(props.has(`BindPaths=${real}:/run/bridge.sock`));
  assert(props.has('InaccessiblePaths=-/run/dbus -/run/systemd'));
  const denoArgs = argv.slice(argv.indexOf('--') + 1);
  assert(!denoArgs.some((a) => a.includes(real)), 'real socket name is not on the worker argv');
  assertEquals(
    denoArgs.includes('--allow-net=unix:/run/bridge.sock'),
    unixSocketNeedsNet(Deno.version.deno),
  );
});

Deno.test('finding 2: the worker refuses a connector init without the bridge secret', () => {
  const init = {
    t: 'init',
    connectionUUID: ASSIGNMENT.connectionUUID,
    mode: 'test',
    protocol: 'ssh',
    target: { address: '10.20.30.40', port: 22 },
    transport: 'connector',
    bridge: '/run/bridge.sock',
    shellDialect: 'linux',
    username: 'u',
    level: 'n1',
    hostKey: { pinned: null },
    tls: { pinned: null },
    terminal: { cols: 80, rows: 24 },
    limits: {},
    recording: false,
  };
  validateInit({ ...init, bridgeSecret: 'a'.repeat(64) });
  for (const bad of [{}, { bridgeSecret: 'xyz' }]) {
    let threw = false;
    try {
      validateInit({ ...init, ...bad });
    } catch {
      threw = true;
    }
    assert(threw);
  }
});

// ---- scripts

const read = (path: string) => Deno.readTextFileSync(`${ROOT}/${path}`);

Deno.test('findings 6, 8, 12, 13, 14: install, update and unit hardening', () => {
  const install = read('scripts/install-connector.sh');
  assertMatch(install, /must not be passed in the environment/);
  assertMatch(install, /read -r -n 129 TOKEN/);
  assertMatch(install, /read -r -s -p .*<\/dev\/tty/);
  assert(install.indexOf('apt-get update') < install.indexOf('apt-get install'));
  assert(!/MNSCLOUD_CONNECTOR_TOKEN=/.test(read('README.md') + read('docs/runtime-api.md')));
  const update = read('scripts/update-connector.sh');
  assertMatch(update, /^apply\(\) \(/m); // subshell body: set -e is honored
  assertMatch(update, /rollback\(\) \{[\s\S]*connector_render_units/);
  assertMatch(update, /connector_verify_release "\$tag" "\$commit"/);
  const lib = read('scripts/lib/connector.sh');
  assertMatch(lib, /RUNTIME_KIT_COMMIT="[0-9a-f]{40}"/);
  assertMatch(lib, /IPAddressDeny=localhost link-local multicast/);
  assertMatch(lib, /older than the running/);
  assertMatch(read('scripts/uninstall-connector.sh'), /mnscloud-access-connector-runtime-kit/);
});

Deno.test('lab finding: the service user must be able to execute Deno (installer bin dir 0700)', () => {
  const lib = read('scripts/lib/connector.sh');
  assertMatch(
    lib,
    /connector_check_service_exec\(\) \{[\s\S]*chmod go\+rx \/usr\/local\/deno[\s\S]*runuser -u "\$CONNECTOR_USER" -- "\$DENO_BIN" --version/,
  );
  const install = read('scripts/install-connector.sh');
  assert(install.indexOf('useradd --system') < install.indexOf('connector_check_service_exec'));
  assert(install.indexOf('connector_check_service_exec') < install.indexOf('systemctl enable'));
  assertMatch(
    read('scripts/update-connector.sh'),
    / connector_ensure_deno\n connector_check_service_exec\n/,
  );
});

Deno.test('finding 8: a downgrade or a tag/commit mismatch is refused before any checkout', async () => {
  const dir = await tempDir('agw-rel-');
  const sh = async (script: string) => {
    const out = await new Deno.Command('bash', {
      args: ['-c', script],
      cwd: dir,
      stdout: 'piped',
      stderr: 'piped',
      env: {
        GIT_AUTHOR_NAME: 't',
        GIT_AUTHOR_EMAIL: 't@example.com',
        GIT_COMMITTER_NAME: 't',
        GIT_COMMITTER_EMAIL: 't@example.com',
      },
    }).output();
    return { code: out.code, err: new TextDecoder().decode(out.stderr) };
  };
  const setup = await sh(`set -e
git init -q origin && cd origin
echo 0.1.0 > VERSION && git add . && git commit -qm one && git tag v0.1.0
echo 0.2.0 > VERSION && git commit -qam two && git tag v0.2.0
cd .. && git clone -q origin app && git -C app checkout -q --detach v0.2.0`);
  assertEquals(setup.code, 0, setup.err);
  const verify = (tag: string, commit: string) =>
    sh(
      `source ${ROOT}/scripts/lib/connector.sh; CONNECTOR_APP_DIR="${dir}/app"; connector_verify_release ${tag} ${commit}`,
    );
  const old = (await sh('git -C origin rev-parse v0.1.0')).err;
  assertEquals(old, '');
  const rev = async (tag: string) => {
    const out = await new Deno.Command('git', {
      args: ['-C', `${dir}/origin`, 'rev-parse', tag],
      stdout: 'piped',
    }).output();
    return new TextDecoder().decode(out.stdout).trim();
  };
  const downgrade = await verify('v0.1.0', await rev('v0.1.0'));
  assertEquals(downgrade.code, 1);
  assertMatch(downgrade.err, /older than the running/);
  const mismatch = await verify('v0.2.0', await rev('v0.1.0'));
  assertEquals(mismatch.code, 1);
  assertMatch(mismatch.err, /does not match the expected commit/);
  assertEquals((await verify('v0.2.0', await rev('v0.2.0'))).code, 0);
  await Deno.remove(dir, { recursive: true });
});

Deno.test('lab finding: the service unit grants every sys API the connector runtime calls', () => {
  const unit = read('scripts/lib/connector.sh').match(
    /--allow-sys=([A-Za-z,]+) \$CONNECTOR_APP_DIR/,
  );
  assert(unit, 'service ExecStart --allow-sys not found');
  const granted = new Set(unit[1].split(','));
  const SYS = [
    'hostname',
    'networkInterfaces',
    'uid',
    'gid',
    'osRelease',
    'osUptime',
    'loadavg',
    'systemMemoryInfo',
  ];
  const used = new Set<string>();
  for (const dir of ['src/connector', 'src/shared']) {
    for (const entry of Deno.readDirSync(`${ROOT}/${dir}`)) {
      if (!entry.name.endsWith('.ts')) continue;
      const source = read(`${dir}/${entry.name}`);
      for (const name of SYS) if (source.includes(`Deno.${name}(`)) used.add(name);
    }
  }
  assert(used.has('uid'), 'key file owner check uses Deno.uid()');
  for (const name of used) assert(granted.has(name), `--allow-sys lacks ${name}`);
});

Deno.test('lab finding: a tunnel the API no longer records is attached again, or closed', async () => {
  // 'none' (a disable/enable cleared the record while the socket stayed up): attach again, keep it.
  let attachment: 'here' | 'none' | 'other' = 'here';
  let attachError: Error | null = null;
  const { hub, calls } = hubWith({
    connector: () => Promise.resolve({ publicKey: PUBLIC_KEY, attachment }),
    connectorAttach: (u) => {
      calls.push(`attach:${u}`);
      return attachError ? Promise.reject(attachError) : Promise.resolve();
    },
  });
  const socket = new FakeSocket();
  hub.attach(socket);
  await hello(socket);
  await settle();
  assertEquals(calls, [`attach:${CONNECTOR}`]);
  await settle(60);
  assertEquals(calls.length, 1); // 'here': nothing to do
  attachment = 'none';
  await settle(60);
  assert(calls.length >= 2 && calls.every((c) => c === `attach:${CONNECTOR}`));
  assertEquals(socket.closed, null);
  assert(hub.has(CONNECTOR));
  // A transient attach failure keeps the tunnel; a refusal closes it.
  attachError = new Error('down');
  await settle(60);
  assertEquals(socket.closed, null);
  attachError = new AttachRefused('Access connector not found');
  await settle(80);
  assertEquals(socket.closed?.[0], 4503);
  assert(!hub.has(CONNECTOR));

  // 'other': another gateway holds the connector now.
  const other = hubWith({
    connector: () => Promise.resolve({ publicKey: PUBLIC_KEY, attachment: 'other' as const }),
  });
  const s2 = new FakeSocket();
  other.hub.attach(s2);
  await hello(s2);
  await settle(80);
  assertEquals(s2.closed?.[0], 4409);
  assert(!other.hub.has(CONNECTOR));
});

Deno.test('lab finding: runtime API maps the attachment and turns attach refusals into AttachRefused', async () => {
  const { RuntimeApi } = await import('../src/controller/runtime_api.ts');
  const { ControlPlaneRejected } = await import('../src/controller/control_plane.ts');
  let reply: unknown = null;
  let reject: Error | null = null;
  const cp = {
    call: () => (reject ? Promise.reject(reject) : Promise.resolve(reply)),
  } as unknown as ConstructorParameters<typeof RuntimeApi>[0];
  const api = new RuntimeApi(cp);
  for (
    const [sent, got] of [['none', 'none'], ['other', 'other'], ['here', 'here'], [
      undefined,
      'here',
    ]]
  ) {
    reply = { publicKey: PUBLIC_KEY, attachment: sent };
    assertEquals((await api.connector(CONNECTOR))?.attachment, got);
  }
  reject = new ControlPlaneRejected(404, 'ACCESS_CONNECTOR_NOT_FOUND');
  assertEquals(await api.connector(CONNECTOR), null);
  const refused = await api.connectorAttach(CONNECTOR).then(() => null, (e) => e);
  assert(refused instanceof AttachRefused);
  reject = new ControlPlaneRejected(502, '');
  const transient = await api.connectorAttach(CONNECTOR).then(() => null, (e) => e);
  assert(transient instanceof ControlPlaneRejected && !(transient instanceof AttachRefused));
});
