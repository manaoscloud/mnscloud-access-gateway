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

function api(
  finished: Map<string, FinishBody>,
  attach: SessionApi['attach'] = () => Promise.resolve({ role: 'operator' }),
): SessionApi {
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
    attach,
    detach: () => Promise.resolve(),
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
  attach?: SessionApi['attach'],
) {
  return new Gateway({
    gatewayKey: 'gw-test1',
    edgeSources: ['10.0.0.5/32'],
    denylist: buildDenylist({ environment, labTargets }),
    capacity: 2,
    version: '0.1.0',
    ticketArrivalMs: 300,
    deps: {
      api: api(finished, attach),
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

Deno.test({
  name:
    'gateway: attach tickets reattach a detachable console with a replay; the API can refuse; a spent ticket is gone',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const key = generateHostKey();
    const device = await startDevice(key);
    const finished = new Map<string, FinishBody>();
    const roles: string[] = [];
    let refuse = false;
    const g = gateway(finished, 'development', ['127.0.0.1/32'], (_uuid, sha) => {
      roles.push(sha);
      return refuse ? Promise.reject(new Error('refused')) : Promise.resolve({ role: 'observer' });
    });
    const server = Deno.serve(
      { hostname: '127.0.0.1', port: 0, onListen: () => {} },
      (request, info) => g.handle(request, (info.remoteAddr as Deno.NetAddr).hostname),
    );
    const base = `ws://127.0.0.1:${server.addr.port}/access-gateway/gw-test1/ws?ticket=`;
    const ticket = newTicket();
    const uuid = crypto.randomUUID();
    await g.accept({
      ...ASSIGNMENT,
      connectionUUID: uuid,
      username: 'support',
      detachable: true,
      target: { address: '127.0.0.1', port: device.port },
      hostKey: { pinned: fingerprintOf(key) },
      ticket: {
        sha256: await ticketHash(ticket),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
      },
    });
    const first = new WebSocket(base + ticket);
    const firstFrames: string[] = [];
    first.onmessage = (e) => {
      firstFrames.push(String(e.data));
      if (e.data === 'OK') first.send('0:8:/export\r');
    };
    const waitFor = async (predicate: () => boolean) => {
      for (let i = 0; i < 500 && !predicate(); i++) await new Promise((r) => setTimeout(r, 20));
      assert(predicate(), 'condition');
    };
    await waitFor(() => firstFrames.join('').includes('service=pppoe'));
    // The browser leaves: the session stays (detachable).
    first.close();
    await new Promise((r) => setTimeout(r, 200));
    assertEquals(finished.has(uuid), false);
    assertEquals(g.sessions.has(uuid), true);

    // An attach ticket for a connection that is not live here is ignored.
    const stranger = newTicket();
    g.addAttachTickets([{
      connectionUUID: crypto.randomUUID(),
      sha256: await ticketHash(stranger),
      expiresAt: new Date(Date.now() + 30000).toISOString(),
      role: 'operator',
    }]);
    assertEquals(g.attachTickets.size, 0);

    const attachTicket = newTicket();
    const entry = {
      connectionUUID: uuid,
      sha256: await ticketHash(attachTicket),
      expiresAt: new Date(Date.now() + 30000).toISOString(),
      role: 'observer' as const,
    };
    g.addAttachTickets([entry, entry]);
    assertEquals(g.attachTickets.size, 1);
    // The API refuses: 401 before any upgrade.
    refuse = true;
    const refused = new WebSocket(base + attachTicket);
    assertEquals(
      await new Promise<string>((resolve) => {
        refused.onerror = () => resolve('error');
        refused.onopen = () => resolve('open');
      }),
      'error',
    );
    // The refused ticket was spent: a second try is also 401 (single use on the gateway too).
    refuse = false;
    g.addAttachTickets([{ ...entry, sha256: await ticketHash(newTicket()) }]);
    const good = newTicket();
    g.addAttachTickets([{ ...entry, sha256: await ticketHash(good) }]);
    const second = new WebSocket(base + good);
    const frames: string[] = [];
    second.onmessage = (e) => frames.push(String(e.data));
    await waitFor(() => frames.join('').includes('service=pppoe'));
    assertEquals(frames[1], 'OK');
    assertEquals(roles.at(-1), await ticketHash(good));
    // Observer input is ignored; the same ticket cannot be used again.
    second.send('0:6:/quit\r');
    await new Promise((r) => setTimeout(r, 200));
    assertEquals(finished.has(uuid), false);
    const again = new WebSocket(base + good);
    assertEquals(
      await new Promise<string>((resolve) => {
        again.onerror = () => resolve('error');
        again.onopen = () => resolve('open');
      }),
      'error',
    );
    second.close();
    g.sessions.get(uuid)?.close('test');
    await g.sessions.get(uuid)?.done;
    await g.drain('test', 100);
    await server.shutdown();
    await device.close();
  },
});

Deno.test({
  name: 'gateway: attach tickets are refused for non-detachable consoles and on a role mismatch',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const key = generateHostKey();
    const device = await startDevice(key);
    const finished = new Map<string, FinishBody>();
    const g = gateway(
      finished,
      'development',
      ['127.0.0.1/32'],
      () => Promise.resolve({ role: 'operator' }),
    );
    const server = Deno.serve(
      { hostname: '127.0.0.1', port: 0, onListen: () => {} },
      (request, info) => g.handle(request, (info.remoteAddr as Deno.NetAddr).hostname),
    );
    const base = `ws://127.0.0.1:${server.addr.port}/access-gateway/gw-test1/ws?ticket=`;
    const open = async (detachable: boolean) => {
      const ticket = newTicket();
      const uuid = crypto.randomUUID();
      await g.accept({
        ...ASSIGNMENT,
        connectionUUID: uuid,
        username: 'support',
        detachable,
        target: { address: '127.0.0.1', port: device.port },
        hostKey: { pinned: fingerprintOf(key) },
        ticket: {
          sha256: await ticketHash(ticket),
          expiresAt: new Date(Date.now() + 30000).toISOString(),
        },
      });
      const socket = new WebSocket(base + ticket);
      await new Promise((resolve) => {
        socket.onmessage = (e) => e.data === 'OK' && resolve(null);
      });
      return { uuid, socket };
    };
    const entry = async (uuid: string, role: 'operator' | 'observer') => {
      const ticket = newTicket();
      g.addAttachTickets([{
        connectionUUID: uuid,
        sha256: await ticketHash(ticket),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        role,
      }]);
      return ticket;
    };
    const status = (ticket: string) =>
      new Promise<string>((resolve) => {
        const s = new WebSocket(base + ticket);
        s.onerror = () => resolve('error');
        s.onopen = () => {
          s.close();
          resolve('open');
        };
      });
    const plain = await open(false);
    await entry(plain.uuid, 'operator');
    assertEquals(g.attachTickets.size, 0);
    const live = await open(true);
    // The API says operator but the ticket was issued for an observer: refused.
    assertEquals(await status(await entry(live.uuid, 'observer')), 'error');
    assertEquals(await status(await entry(live.uuid, 'operator')), 'open');
    for (const c of [plain, live]) {
      c.socket.close();
      g.sessions.get(c.uuid)?.close('test');
      await g.sessions.get(c.uuid)?.done;
    }
    await g.drain('test', 100);
    await server.shutdown();
    await device.close();
  },
});
