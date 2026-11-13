// Gateway core: edge-only listener, ticket-gated WebSocket, assignment refusals, and one
// end-to-end console over a real WebSocket to the hostile fake device.

import type { FinishBody } from '../src/controller/contract.ts';
import { buildDenylist } from '../src/controller/denylist.ts';
import { Gateway } from '../src/controller/gateway.ts';
import type { SessionApi } from '../src/controller/session.ts';
import { ticketHash } from '../src/controller/ticket.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import { parseServerFrame } from '../src/shared/framing.ts';
import { assert, assertEquals, assertNotIncludes } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import { fingerprintOf, generateHostKey, PASSWORD, startDevice } from './hostile_ssh_server.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

function api(finished: Map<string, FinishBody>): SessionApi {
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

function gateway(
  finished: Map<string, FinishBody>,
  environment = 'production',
  labTargets: string[] = [],
) {
  return new Gateway({
    gatewayKey: 'gw-test1',
    edgeSources: ['10.0.0.5/32'],
    denylist: buildDenylist({ environment, labTargets }),
    capacity: 2,
    version: '0.1.0',
    ticketArrivalMs: 300,
    deps: {
      api: api(finished),
      unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
      launcher: new DirectLauncher(ROOT),
      networks: null,
      sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
      log: () => {},
    },
  });
}

function newTicket() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(
    /=+$/,
    '',
  );
}

Deno.test({
  name: 'gateway: listener answers only edge sources; ticket and path checks',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const finished = new Map<string, FinishBody>();
    const g = gateway(finished);
    const ws = { headers: { upgrade: 'websocket' } };
    assertEquals((await g.handle(new Request('https://gw/healthz'), '198.51.100.9')).status, 403);
    assertEquals((await g.handle(new Request('https://gw/healthz'), '10.0.0.5')).status, 200);
    assertEquals(
      (await g.handle(new Request('https://gw/access-gateway/other/ws', ws), '10.0.0.5')).status,
      404,
    );
    assertEquals(
      (await g.handle(
        new Request('https://gw/access-gateway/gw-test1/ws?ticket=x', ws),
        '10.0.0.5',
      )).status,
      401,
    );
    assertEquals(
      (await g.handle(new Request(`https://gw/ws?ticket=${newTicket()}`, ws), '10.0.0.5')).status,
      401,
    );
    await g.drain('test', 100);
  },
});

Deno.test({
  name:
    'gateway: a browser that arrives before its assignment waits for it; used tickets never wait',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const finished = new Map<string, FinishBody>();
    const g = gateway(finished, 'development', ['127.0.0.1/32']);
    const ticket = newTicket();
    const ws = { headers: { upgrade: 'websocket' } };
    // Unknown first; the assignment lands 150 ms later (inside the 300 ms test wait).
    const early = g.handle(new Request(`https://gw/ws?ticket=${ticket}`, ws), '10.0.0.5');
    setTimeout(async () => {
      await g.accept({
        ...ASSIGNMENT,
        connectionUUID: crypto.randomUUID(),
        target: { address: '127.0.0.1', port: 1 },
        ticket: {
          sha256: await ticketHash(ticket),
          expiresAt: new Date(Date.now() + 30000).toISOString(),
        },
      });
    }, 150);
    // Not 401: the ticket was found (the upgrade itself needs a real socket, so it throws here).
    const outcome = await early.then((r) => r.status, () => 'upgrade');
    assertEquals(outcome, 'upgrade');
    // The same ticket again is "used": refused at once, without waiting.
    const started = Date.now();
    assertEquals(
      (await g.handle(new Request(`https://gw/ws?ticket=${ticket}`, ws), '10.0.0.5')).status,
      401,
    );
    assert(Date.now() - started < 200);
    await g.drain('test', 100);
  },
});

Deno.test({
  name:
    'gateway: refuses denylisted destinations, Telnet/8728 and over-capacity; expires unused tickets',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const finished = new Map<string, FinishBody>();
    const g = gateway(finished);
    const base = {
      ...ASSIGNMENT,
      target: { address: '8.8.8.8', port: 22 },
      ticket: {
        sha256: await ticketHash(newTicket()),
        expiresAt: new Date(Date.now() + 1000).toISOString(),
      },
    };
    const cases: [Record<string, unknown>, string][] = [
      [{ target: { address: '169.254.169.254', port: 22 } }, 'destination_refused'],
      [{ target: { address: '10.0.0.10', port: 22 } }, 'destination_refused'],
      [{ target: { address: '127.0.0.1', port: 22 } }, 'destination_refused'],
      [{ target: { address: '8.8.8.8', port: 23 } }, 'protocol_refused'],
      [{ target: { address: '8.8.8.8', port: 8728 } }, 'protocol_refused'],
      [{ protocol: 'telnet' }, 'protocol_refused'],
      [{ target: { address: 'router.example.com', port: 22 } }, 'invalid_assignment'],
    ];
    for (const [patch, reason] of cases) {
      const uuid = crypto.randomUUID();
      assertEquals(await g.accept({ ...base, ...patch, connectionUUID: uuid }), 'refused', reason);
      assertEquals(finished.get(uuid)?.reason, reason);
    }
    const waiting = [crypto.randomUUID(), crypto.randomUUID()];
    for (const uuid of waiting) {
      assertEquals(
        await g.accept({
          ...base,
          connectionUUID: uuid,
          ticket: { ...base.ticket, sha256: await ticketHash(newTicket()) },
        }),
        'waiting',
      );
    }
    const full = crypto.randomUUID();
    assertEquals(await g.accept({ ...base, connectionUUID: full }), 'refused');
    assertEquals(finished.get(full)?.reason, 'gateway_full');
    g.sweep(Date.now() + 5000);
    assertEquals(waiting.map((u) => finished.get(u)?.reason), ['ticket_expired', 'ticket_expired']);
    // DEV lab /32 exception (development only).
    const dev = gateway(finished, 'development', ['10.20.30.40/32']);
    assertEquals(
      await dev.accept({
        ...base,
        connectionUUID: crypto.randomUUID(),
        target: { address: '10.20.30.40', port: 22 },
      }),
      'waiting',
    );
    await g.drain('test', 100);
    await dev.drain('test', 100);
  },
});

Deno.test({
  name: 'gateway: end-to-end console over a real WebSocket with a single-use ticket',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const key = generateHostKey();
    const device = await startDevice(key);
    const finished = new Map<string, FinishBody>();
    const g = gateway(finished, 'development', ['127.0.0.1/32']);
    const server = Deno.serve(
      { hostname: '127.0.0.1', port: 0, onListen: () => {} },
      (request, info) => g.handle(request, (info.remoteAddr as Deno.NetAddr).hostname),
    );
    const ticket = newTicket();
    const uuid = crypto.randomUUID();
    assertEquals(
      await g.accept({
        ...ASSIGNMENT,
        connectionUUID: uuid,
        username: 'support',
        target: { address: '127.0.0.1', port: device.port },
        hostKey: { pinned: fingerprintOf(key) },
        ticket: {
          sha256: await ticketHash(ticket),
          expiresAt: new Date(Date.now() + 30000).toISOString(),
        },
      }),
      'waiting',
    );
    const url = `ws://127.0.0.1:${server.addr.port}/access-gateway/gw-test1/ws?ticket=${ticket}`;
    const frames: string[] = [];
    const socket = new WebSocket(url);
    const closed = new Promise<number>((resolve) => (socket.onclose = (e) => resolve(e.code)));
    socket.onmessage = (e) => {
      frames.push(String(e.data));
      if (e.data === 'OK') socket.send('0:8:/export\r');
      if (String(e.data).includes('service=pppoe')) socket.send('0:6:/quit\r');
    };
    assertEquals(await closed, 1000);
    const output = frames.map(parseServerFrame).filter((f) => f?.kind === 'output').map((f) =>
      (f as { data: string }).data
    ).join('');
    assert(output.includes('password=********'));
    assertNotIncludes(frames.join(''), PASSWORD);
    // The ticket was single use.
    const again = new WebSocket(url);
    const refused = await new Promise<string>((resolve) => {
      again.onerror = () => resolve('error');
      again.onopen = () => resolve('open');
    });
    assertEquals(refused, 'error');
    await new Promise((r) => setTimeout(r, 100));
    assertEquals(finished.get(uuid)?.reason, 'device_closed');
    await g.drain('test', 100);
    await server.shutdown();
    await device.close();
  },
});
