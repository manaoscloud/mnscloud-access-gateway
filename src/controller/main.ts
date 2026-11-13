// Controller (mnscloud-access-gateway.service, root). Reads the node binding, uses the host Agent
// identity, applies the host firewall from /config, serves the WebSocket listener (TLS, 7443),
// long-polls assignments and sends heartbeats. Sessions run in their own sandboxes.

import { parseCidr } from '../shared/ip.ts';
import { type GatewayConfig, parseAttachTickets, parseConfig } from './contract.ts';
import { ControlPlane, loadAgentIdentity, privateRead } from './control_plane.ts';
import { ConnectorHub } from './connector_hub.ts';
import { buildDenylist } from './denylist.ts';
import { readEnvFile, requireBinding } from './env.ts';
import { Gateway } from './gateway.ts';
import { denoCapture, FileKeyStore, MgmtVpn } from './mgmt_vpn.ts';
import { denoRunner, NETNS_PREFIX, renderHostNft, SessionNetworks } from './netns.ts';
import { openVaultUnwrapper } from './openvault.ts';
import { RuntimeApi } from './runtime_api.ts';
import { UNIT_PREFIX } from './sandbox.ts';
import { SystemdLauncher } from './worker_launcher.ts';

const ROOT = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');
const TLS_DIR = '/etc/mnscloud/access-gateway/tls';

function log(message: string) {
  console.log(`[mnscloud-access-gateway] ${message}`);
}

async function applyHostFirewall(config: GatewayConfig, mgmtVpn?: MgmtVpn) {
  const script = renderHostNft({
    denylist: buildDenylist(config),
    edgeSources: config.edgeSources.map((c) => parseCidr(c)!),
    listenPort: config.listen.port,
    pool4: config.sessionNetwork.ipv4,
    pool6: config.sessionNetwork.ipv6,
    mgmtNet: mgmtVpn?.mgmtNet ?? null,
  });
  const result = await denoRunner(['nft', '-f', '-'], script);
  if (result.code !== 0) throw new Error(`host firewall not applied: ${result.stderr}`);
  mgmtVpn?.markNftApplied(mgmtVpn.mgmtNet);
}

/** Leftovers of a previous controller (crash, kill): no worker or namespace survives it. */
async function cleanupLeftovers() {
  await denoRunner(['systemctl', 'kill', '--signal=KILL', `${UNIT_PREFIX}*`]).catch(() => {});
  await denoRunner(['systemctl', 'reset-failed', `${UNIT_PREFIX}*`]).catch(() => {});
  const list = await new Deno.Command('ip', {
    args: ['netns', 'list'],
    stdout: 'piped',
    stderr: 'null',
  }).output();
  for (const line of new TextDecoder().decode(list.stdout).split('\n')) {
    const name = line.split(' ')[0];
    if (name.startsWith(NETNS_PREFIX) && /^[a-z0-9-]+$/.test(name)) {
      await denoRunner(['ip', 'netns', 'delete', name]);
    }
  }
}

async function main() {
  const envIndex = Deno.args.indexOf('--env');
  const envPath = envIndex >= 0 ? Deno.args[envIndex + 1] : '/etc/mnscloud/access-gateway.env';
  const binding = requireBinding(readEnvFile(envPath));
  const identity = loadAgentIdentity(binding.api);
  const api = new RuntimeApi(new ControlPlane(identity));
  const version = Deno.readTextFileSync(`${ROOT}/VERSION`).trim();

  let config = parseConfig(await api.config());
  if (config.gatewayUUID !== binding.gatewayUUID) {
    throw new Error('Configuration belongs to another gateway');
  }
  await cleanupLeftovers();
  const mgmtVpn = new MgmtVpn({
    api,
    run: denoRunner,
    capture: denoCapture,
    keys: new FileKeyStore(),
    log,
  });
  await applyHostFirewall(config);
  const networks = new SessionNetworks(
    denoRunner,
    config.capacity.maxSessions,
    config.sessionNetwork.ipv4,
    config.sessionNetwork.ipv6,
    mgmtVpn,
  );
  const hub = new ConnectorHub({
    gatewayKey: config.gatewayKey,
    api,
    maxStreams: () => config.capacity.maxSessions,
    log,
  });
  const gateway = new Gateway({
    hub,
    gatewayKey: config.gatewayKey,
    listenAddress: config.listen.address,
    edgeSources: config.edgeSources,
    denylist: buildDenylist(config),
    capacity: config.capacity.maxSessions,
    version,
    deps: {
      api,
      connectors: hub,
      unwrap: openVaultUnwrapper(config.openvault.address, config.openvault.caCertificatePem),
      launcher: new SystemdLauncher(ROOT),
      networks,
      sandbox: config.sandbox,
      log,
    },
  });

  const cert = privateRead(`${TLS_DIR}/cert.pem`);
  const key = privateRead(`${TLS_DIR}/key.pem`);
  const server = Deno.serve({
    hostname: config.listen.address,
    port: config.listen.port,
    cert,
    key,
    onListen: ({ hostname, port }) => log(`listening on ${hostname}:${port}`),
  }, (request, info) => gateway.handle(request, (info.remoteAddr as Deno.NetAddr).hostname));

  let running = true;
  const stop = async () => {
    if (!running) return;
    running = false;
    mgmtVpn.stop();
    log('stopping: closing sessions');
    await gateway.drain('gateway_shutdown');
    await server.shutdown();
    await cleanupLeftovers();
    Deno.exit(0);
  };
  Deno.addSignalListener('SIGTERM', () => void stop());
  Deno.addSignalListener('SIGINT', () => void stop());

  const certificateSha256 = await sha256Hex(pemToDer(cert));
  const started = Date.now();
  const heartbeat = async () => {
    try {
      const reply = await api.heartbeat({
        version,
        configDigest: config.configDigest,
        activeSessions: gateway.activeSessions,
        freeSlots: gateway.freeSlots,
        sessions: [...gateway.sessions.keys()],
        listenerCertificateSha256: certificateSha256,
        listenerCertificatePem: cert,
        uptimeSeconds: Math.floor((Date.now() - started) / 1000),
      });
      if (reply?.configDigest && reply.configDigest !== config.configDigest) {
        const next = parseConfig(await api.config());
        if (
          next.listen.address !== config.listen.address || next.listen.port !== config.listen.port
        ) {
          log('listener changed: restarting');
          await stop();
          return;
        }
        await applyHostFirewall(next, mgmtVpn);
        gateway.update({
          edgeSources: next.edgeSources,
          denylist: buildDenylist(next),
          capacity: next.capacity.maxSessions,
        });
        config = next;
        log('configuration refreshed');
      }
    } catch (error) {
      log(`heartbeat failed: ${(error as Error).message}`);
    }
  };
  mgmtVpn.start();
  await heartbeat();
  setInterval(heartbeat, 30000);

  let cursor = '';
  while (running) {
    try {
      const batch = await api.assignments(cursor, 25, gateway.freeSlots);
      cursor = typeof batch?.cursor === 'string' ? batch.cursor.slice(0, 256) : cursor;
      for (const uuid of batch?.cancelled ?? []) gateway.cancel(String(uuid));
      for (const raw of batch?.assignments ?? []) await gateway.accept(raw);
      gateway.addAttachTickets(parseAttachTickets(batch?.attachTickets));
    } catch (error) {
      log(`assignments poll failed: ${(error as Error).message}`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

async function sha256Hex(bytes: Uint8Array) {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    log(`fatal: ${(error as Error).message}`);
    Deno.exit(1);
  }
}
