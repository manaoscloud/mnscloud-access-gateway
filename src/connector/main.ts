// Remote access connector (mnscloud-access-connector.service, unprivileged user).
//
//   run      heartbeat (30 s), configuration (60 s), outbound tunnel to the assigned gateway
//   claim    installation: generates the Ed25519 key on this host and claims the single-use token
//            (read from stdin, never from arguments); only the public key leaves the host
//   desired  prints the release the platform wants this connector to run (used by the updater)
//
// It never executes commands and never listens on any port.

import { canonicalApi } from '../controller/control_plane.ts';
import { b64urlEncode, generateKeyPair, importPrivateKey } from '../shared/connector_auth.ts';
import { ownAddressesOf, reportedAddresses } from '../shared/destination.ts';
import { ApiRejected, claim, ConnectorApi } from './api.ts';
import {
  DEFAULT_CONFIG_PATH,
  parseLocalConfig,
  parseRemoteConfig,
  readPrivateKeyFile,
  type RemoteConfig,
} from './config.ts';
import { dialWithTimeout, handleOpen } from './open.ts';
import { backoffMs, runTunnel } from './tunnel.ts';

const ROOT = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');

function log(message: string) {
  console.log(`[mnscloud-access-connector] ${message}`);
}

function option(name: string): string | undefined {
  const index = Deno.args.indexOf(name);
  return index >= 0 ? Deno.args[index + 1] : undefined;
}

function version() {
  return Deno.readTextFileSync(`${ROOT}/VERSION`).trim();
}

async function loadApi() {
  const config = parseLocalConfig(Deno.readTextFileSync(option('--config') ?? DEFAULT_CONFIG_PATH));
  const key = await importPrivateKey(readPrivateKeyFile(config.keyFile));
  return { config, api: new ConnectorApi(config.apiUrl, config.connectorUuid, key), key };
}

async function run() {
  const { config, api, key } = await loadApi();
  let remote: RemoteConfig = { allowedCidrs: [], gateway: null, release: null };
  let haveConfig = false;
  let tunnelUp = false;
  let current: AbortController | null = null;
  let currentGateway = '';
  let running = true;

  const refreshConfig = async () => {
    try {
      const next = parseRemoteConfig(await api.config(), config.apiUrl);
      if (!next) {
        log('configuration refused: it does not match the contract');
        return;
      }
      remote = next;
      haveConfig = true;
      // Follow a gateway change or an unassignment.
      const wanted = next.gateway ? next.gateway.relayUrl : '';
      if (current && wanted !== currentGateway) current.abort();
    } catch (error) {
      log(`configuration failed: ${(error as Error).message}`);
    }
  };

  const heartbeat = async () => {
    try {
      await api.heartbeat({
        version: version(),
        host: Deno.hostname().slice(0, 253),
        addresses: reportedAddresses(Deno.networkInterfaces()),
        tunnelState: tunnelUp ? 'connected' : 'disconnected',
      });
    } catch (error) {
      log(`heartbeat failed: ${(error as Error).message}`);
    }
  };

  await refreshConfig();
  await heartbeat();
  setInterval(heartbeat, 30000);
  setInterval(refreshConfig, 60000);

  const stop = () => {
    running = false;
    current?.abort();
    setTimeout(() => Deno.exit(0), 500);
  };
  Deno.addSignalListener('SIGTERM', stop);
  Deno.addSignalListener('SIGINT', stop);

  let failures = 0;
  while (running) {
    const gateway = haveConfig ? remote.gateway : null;
    if (!gateway) {
      await new Promise((resolve) => setTimeout(resolve, 5000)); // NOSONAR: sequential loop
      continue;
    }
    current = new AbortController();
    currentGateway = gateway.relayUrl;
    const startedAt = Date.now();
    log(`connecting tunnel to gateway ${gateway.key}`);
    const ready = await runTunnel({ // NOSONAR: sequential loop
      relayUrl: gateway.relayUrl,
      gatewayKey: gateway.key,
      connectorUuid: config.connectorUuid,
      key,
      log,
      onReady: () => {
        tunnelUp = true;
        log('tunnel ready');
        void heartbeat();
      },
      onOpen: (mux, id, spec) => {
        void handleOpen(mux, id, spec, {
          policy: () => ({
            allowedCidrs: remote.allowedCidrs,
            ownAddresses: ownAddressesOf(Deno.networkInterfaces()),
          }),
          accept: (uuid, host, port, signal) => api.accept(uuid, host, port, signal),
          connect: dialWithTimeout,
          log,
        });
      },
    }, current.signal);
    if (tunnelUp) {
      tunnelUp = false;
      void heartbeat();
    }
    failures = ready && Date.now() - startedAt > 30000 ? 0 : failures + 1;
    if (running) await new Promise((resolve) => setTimeout(resolve, backoffMs(failures))); // NOSONAR: sequential loop
  }
}

async function readStdinLine(): Promise<string> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of Deno.stdin.readable) {
    chunks.push(chunk);
    total += chunk.length;
    if (total > 4096) throw new Error('Input too long');
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(out).trim();
}

async function claimInstallation() {
  const apiUrl = canonicalApi(option('--api-url') ?? '');
  const configPath = option('--config') ?? DEFAULT_CONFIG_PATH;
  const keyFile = option('--key-file') ?? configPath.replace(/connector\.json$/, 'key.pkcs8');
  const token = await readStdinLine();
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) throw new Error('Invalid installation token');
  const pair = await generateKeyPair();
  // The private key is written first, 0600, and never printed or sent anywhere.
  await Deno.writeTextFile(keyFile, b64urlEncode(pair.pkcs8) + '\n', {
    mode: 0o600,
    createNew: true,
  });
  try {
    const claimed = await claim(apiUrl, {
      token,
      publicKey: pair.publicKey,
      host: Deno.hostname().slice(0, 253),
      version: version(),
    });
    await Deno.writeTextFile(
      configPath,
      JSON.stringify({ apiUrl, connectorUuid: claimed.connectorUuid, keyFile }, null, 2) + '\n',
      { mode: 0o640 },
    );
    log(`claimed as connector ${claimed.connectorUuid}`);
  } catch (error) {
    await Deno.remove(keyFile).catch(() => {});
    if (error instanceof ApiRejected) throw new Error(`claim refused (HTTP ${error.status})`);
    throw error;
  }
}

async function desired() {
  const { config, api } = await loadApi();
  const remote = parseRemoteConfig(await api.config(), config.apiUrl);
  if (remote?.release) console.log(JSON.stringify(remote.release));
}

if (import.meta.main) {
  try {
    const command = Deno.args[0] ?? 'run';
    if (command === 'run') await run();
    else if (command === 'claim') await claimInstallation();
    else if (command === 'desired') await desired();
    else throw new Error('Usage: main.ts run|claim|desired');
  } catch (error) {
    log(`fatal: ${(error as Error).message}`);
    Deno.exit(1);
  }
}
