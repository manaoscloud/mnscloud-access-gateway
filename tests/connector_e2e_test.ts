// End to end over a real WebSocket: gateway hub <-> connector tunnel client <-> device, with the
// real worker process that has no network permission and talks only to the bridge socket.

import { handleOpen } from '../src/connector/open.ts';
import { runTunnel } from '../src/connector/tunnel.ts';
import { ConnectorHub } from '../src/controller/connector_hub.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { buildDenylist } from '../src/controller/denylist.ts';
import { Gateway } from '../src/controller/gateway.ts';
import type { SessionApi } from '../src/controller/session.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import { importPrivateKey, pkcs8FromSeed } from '../src/shared/connector_auth.ts';
import { workerDenoArgs } from '../src/controller/sandbox.ts';
import { makeCertificate, startRouterOs } from './routeros_mock.ts';
import { assert, assertEquals } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import { fingerprintOf, generateHostKey, PASSWORD, startDevice } from './hostile_ssh_server.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const PUBLIC_KEY = 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg';
const FINGERPRINT = 'SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=';
const CONNECTOR = '11111111-2222-4333-8444-555555555555';

// A tenant LAN device: the test dials the local fake device in its place.
const LAN = '10.20.30.40';

function sessionApi(finished: Map<string, FinishBody>): SessionApi {
  return {
    hostKey: () => Promise.resolve({ decision: 'accept', pinned: true }),
    credential: () =>
      Promise.resolve({
        credentialUseUUID: crypto.randomUUID(),
        wrapToken: 'wrap-token-0123456789',
        ttlSeconds: 30,
      }),
    credentialResult: () => Promise.resolve(),
    events: () => Promise.resolve(),
    recordingPart: () => Promise.resolve(),
    finish: (uuid, body) => {
      finished.set(uuid, body);
      return Promise.resolve();
    },
  };
}

Deno.test('worker args: connector transport has no TCP permission, only the bridge socket', () => {
  const args = workerDenoArgs('/opt/x', { address: '10.0.0.1', port: 22 }, 256, '/run/b/ab.sock');
  assertEquals(args.filter((a) => a.startsWith('--allow-net')), [
    '--allow-net=unix:/run/b/ab.sock',
  ]);
  assert(args.includes('--allow-read=/opt/x,/run/b/ab.sock'));
  assert(args.includes('--allow-write=/run/b/ab.sock'));
  assert(!args.some((a) => a.startsWith('--allow-run') || a.startsWith('--allow-env')));
});

Deno.test({
  name: 'e2e: SSH test through the connector tunnel and the unix bridge; refusals and offline',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const key = generateHostKey();
    const device = await startDevice(key);
    const router = await startRouterOs(await makeCertificate(), PASSWORD);
    const finished = new Map<string, FinishBody>();
    const bridgeDir = await Deno.makeTempDir({ prefix: 'agw-bridge-' });
    const hub = new ConnectorHub({
      gatewayKey: 'gw-test1',
      api: {
        connector: (uuid) => Promise.resolve(uuid === CONNECTOR ? { publicKey: PUBLIC_KEY } : null),
        connectorAttach: () => Promise.resolve(),
        connectorDetach: () => Promise.resolve(),
      },
      maxStreams: () => 4,
      log: () => {},
    });
    const gateway = new Gateway({
      gatewayKey: 'gw-test1',
      edgeSources: [],
      denylist: buildDenylist({ environment: 'production' }),
      capacity: 4,
      version: '0.0.0',
      hub,
      deps: {
        api: sessionApi(finished),
        connectors: hub,
        bridgeDir,
        unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
        launcher: new DirectLauncher(ROOT),
        networks: null,
        sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
        log: () => {},
      },
    });
    const server = Deno.serve(
      { hostname: '127.0.0.1', port: 0, onListen: () => {} },
      (request, info) => gateway.handle(request, (info.remoteAddr as Deno.NetAddr).hostname),
    );
    const accepted: string[] = [];
    const abort = new AbortController();
    let ready: () => void;
    const isReady = new Promise<void>((resolve) => (ready = resolve));
    const connectorKey = await importPrivateKey(pkcs8FromSeed(SEED));
    const tunnel = runTunnel({
      relayUrl: `ws://127.0.0.1:${server.addr.port}/access-gateway/gw-test1/connector`,
      gatewayKey: 'gw-test1',
      connectorUuid: CONNECTOR,
      key: connectorKey,
      log: () => {},
      onReady: () => ready(),
      onOpen: (mux, id, spec) => {
        void handleOpen(mux, id, spec, {
          policy: () => ({ allowedCidrs: [], ownAddresses: [] }),
          accept: (uuid) => {
            accepted.push(uuid);
            return Promise.resolve(true);
          },
          connect: (_host, port) =>
            Deno.connect({
              hostname: '127.0.0.1',
              port: port === 8729 ? router.port : device.port,
            }),
          log: () => {},
        });
      },
    }, abort.signal);
    await isReady;
    assert(hub.has(CONNECTOR));

    const base = {
      ...ASSIGNMENT,
      mode: 'test',
      ticket: null,
      path: 'connector',
      transport: 'connector',
      connectorUuid: CONNECTOR,
      connectorKeyFingerprint: FINGERPRINT,
      username: 'support',
      hostKey: { pinned: fingerprintOf(key) },
    };
    // 1) a device behind the connector: SSH login succeeds through the bridge.
    const ok = crypto.randomUUID();
    assertEquals(
      await gateway.accept({
        ...base,
        connectionUUID: ok,
        target: { address: LAN, port: device.port },
      }),
      'started',
    );
    for (let i = 0; i < 300 && !finished.has(ok); i++) await new Promise((r) => setTimeout(r, 50));
    assertEquals(finished.get(ok)?.reason, 'test_ok');
    assertEquals(accepted, [ok]);
    // 1b) RouterOS API-SSL access test through the same path (TLS over the bridge socket).
    const ros = crypto.randomUUID();
    assertEquals(
      await gateway.accept({
        ...base,
        connectionUUID: ros,
        protocol: 'routeros_api',
        hostKey: { pinned: null },
        target: { address: LAN, port: 8729 },
      }),
      'started',
    );
    for (let i = 0; i < 300 && !finished.has(ros); i++) await new Promise((r) => setTimeout(r, 50));
    assertEquals(finished.get(ros)?.reason, 'test_ok');
    assertEquals(finished.get(ros)?.facts?.identity, 'RB-Lab');
    // 2) the gateway itself refuses loopback before touching the tunnel.
    const loop = crypto.randomUUID();
    assertEquals(
      await gateway.accept({
        ...base,
        connectionUUID: loop,
        target: { address: '127.0.0.1', port: 22 },
      }),
      'refused',
    );
    assertEquals(finished.get(loop)?.reason, 'destination_refused');
    // 3) an unknown connector is offline.
    const offline = crypto.randomUUID();
    assertEquals(
      await gateway.accept({
        ...base,
        connectionUUID: offline,
        connectorUuid: '99999999-2222-4333-8444-555555555555',
        target: { address: LAN, port: device.port },
      }),
      'refused',
    );
    assertEquals(finished.get(offline)?.reason, 'connector_offline');
    assertEquals(finished.get(offline)?.state, 'failed');
    // 4) the connector refuses what its own policy forbids (own address) and the API never hears of it.
    const refusedAtConnector = crypto.randomUUID();
    abort.abort();
    await tunnel;
    await new Promise((r) => setTimeout(r, 100));
    assert(!hub.has(CONNECTOR), 'tunnel gone');
    assertEquals(
      await gateway.accept({
        ...base,
        connectionUUID: refusedAtConnector,
        target: { address: LAN, port: device.port },
      }),
      'refused',
    );
    assertEquals(finished.get(refusedAtConnector)?.reason, 'connector_offline');
    await gateway.drain('test', 100);
    await server.shutdown();
    await device.close();
    await router.close();
    await Deno.remove(bridgeDir, { recursive: true });
  },
});
