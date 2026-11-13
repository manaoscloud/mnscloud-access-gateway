// Management VPN path ("mgmt_vpn"): a WireGuard interface to the hub that carries the sessions of
// devices reachable only through the management network, with one source address per tenant
// (the hub forwards a tenant's source only to that tenant's addresses).
//
// Pure renderers (wg/ip argv, validation of what the API sends) plus a privileged applier in the
// style of netns.ts. The controller (root) is the only process that runs `wg`, `ip` and `nft`; the
// private key lives in a 0600 file on the host and is never logged, sent or put in an argv.

import { type Cidr, cidrContains, parseAddress, parseCidr } from '../shared/ip.ts';
import { ContractError, type MgmtVpnDesired, UUID } from './contract.ts';
import {
  MGMT_IF,
  type MgmtGate,
  MgmtVpnUnavailable,
  renderMgmtNetNft,
  type Runner,
} from './netns.ts';

export const MGMT_MTU = 1380;
export const MGMT_KEEPALIVE = 25;
export const MGMT_SYNC_MS = 60000;
export const MGMT_KEY_FILE = '/var/lib/mnscloud/access-gateway/mgmt-vpn.key';

const WG_KEY = /^[A-Za-z0-9+/]{43}=$/;
const HOSTNAME =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

function ipv4Cidr(value: unknown, label: string): Cidr {
  const cidr = parseCidr(value);
  if (!cidr || cidr.family !== 4 || cidr.text !== value) {
    throw new ContractError(`Invalid ${label}`);
  }
  return cidr;
}

/** `host:port` with a hostname, an IPv4 literal or a bracketed IPv6 literal. */
export function validEndpoint(value: unknown): boolean {
  if (typeof value !== 'string' || value.length > 270) return false;
  const match = /^(\[[0-9a-fA-F:.]+\]|[^:[\]]+):(\d{1,5})$/.exec(value);
  if (!match) return false;
  const port = Number(match[2]);
  if (port < 1 || port > 65535 || match[2] !== String(port)) return false;
  const host = match[1];
  if (host.startsWith('[')) return parseAddress(host.slice(1, -1))?.family === 6;
  return parseAddress(host)?.family === 4 || (!/^[0-9.]+$/.test(host) && HOSTNAME.test(host));
}

/**
 * Validates the `GET /mgmt-vpn` answer. Null means "no hub" (`{ hub: null }`); anything malformed
 * throws, and the interface is then left as it is.
 */
export function parseMgmtVpn(value: unknown): MgmtVpnDesired | null {
  // deno-lint-ignore no-explicit-any
  const v = value as Record<string, any> | null;
  if (!v || typeof v !== 'object') throw new ContractError('Invalid management VPN');
  if (v.hub === null || v.hub === undefined) return null;
  const hub = v.hub;
  if (typeof hub !== 'object' || !UUID.test(String(hub.uuid))) {
    throw new ContractError('Invalid hub uuid');
  }
  if (!validEndpoint(hub.endpoint)) throw new ContractError('Invalid hub endpoint');
  if (typeof hub.publicKey !== 'string' || !WG_KEY.test(hub.publicKey)) {
    throw new ContractError('Invalid hub public key');
  }
  const mgmtNet = ipv4Cidr(hub.mgmtNet, 'mgmtNet');
  const gatewayNet = ipv4Cidr(hub.gatewayNet, 'gatewayNet');
  // A short prefix would capture the default route; the hub range is a private slice.
  if (mgmtNet.prefix < 8 || mgmtNet.prefix > 30) throw new ContractError('Invalid mgmtNet');
  if (
    gatewayNet.prefix < mgmtNet.prefix ||
    !cidrContains(mgmtNet, { family: 4, value: gatewayNet.base, text: '' })
  ) throw new ContractError('gatewayNet is outside mgmtNet');
  const sources = v.sources ?? [];
  if (!Array.isArray(sources) || sources.length > 4096) {
    throw new ContractError('Invalid sources');
  }
  const seen = new Set<string>();
  for (const source of sources) {
    const address = parseAddress(source);
    if (!address || address.family !== 4 || address.text !== source) {
      throw new ContractError('Invalid source');
    }
    if (!cidrContains(gatewayNet, address)) throw new ContractError('source is outside gatewayNet');
    seen.add(address.text);
  }
  return {
    hub: {
      uuid: hub.uuid,
      endpoint: hub.endpoint,
      publicKey: hub.publicKey,
      mgmtNet: mgmtNet.text,
      gatewayNet: gatewayNet.text,
    },
    sources: [...seen].sort(),
  };
}

/** What the host has now (read before applying; the diff is computed by the pure renderer). */
export interface InterfaceState {
  exists: boolean;
  /** IPv4 addresses with prefix, as `a.b.c.d/n`. */
  addresses: string[];
  peers: string[];
}

/** Commands that bring the interface to the desired state, in order. */
export function renderMgmtVpnApply(
  desired: MgmtVpnDesired,
  current: InterfaceState,
  keyFile = MGMT_KEY_FILE,
): string[][] {
  const { hub } = desired;
  const commands: string[][] = [];
  if (!current.exists) commands.push(['ip', 'link', 'add', MGMT_IF, 'type', 'wireguard']);
  commands.push([
    'wg',
    'set',
    MGMT_IF,
    'private-key',
    keyFile,
    'peer',
    hub.publicKey,
    'endpoint',
    hub.endpoint,
    'allowed-ips',
    hub.mgmtNet,
    'persistent-keepalive',
    String(MGMT_KEEPALIVE),
  ]);
  for (const peer of current.peers) {
    if (peer !== hub.publicKey) commands.push(['wg', 'set', MGMT_IF, 'peer', peer, 'remove']);
  }
  commands.push(['ip', 'link', 'set', 'dev', MGMT_IF, 'mtu', String(MGMT_MTU)]);
  const wanted = new Set(desired.sources.map((s) => `${s}/32`));
  const have = new Set(current.addresses);
  for (const address of wanted) {
    if (!have.has(address)) commands.push(['ip', 'addr', 'add', address, 'dev', MGMT_IF]);
  }
  for (const address of have) {
    if (!wanted.has(address)) commands.push(['ip', 'addr', 'del', address, 'dev', MGMT_IF]);
  }
  commands.push(['ip', 'link', 'set', 'dev', MGMT_IF, 'up']);
  commands.push(['ip', 'route', 'replace', hub.mgmtNet, 'dev', MGMT_IF]);
  return commands;
}

export function renderMgmtVpnRemove(): string[][] {
  return [['ip', 'link', 'delete', 'dev', MGMT_IF]];
}

/** `ip -o -4 addr show` output to the `a.b.c.d/n` list. */
export function parseAddresses(output: string): string[] {
  const out: string[] = [];
  for (const line of output.split('\n')) {
    const match = /\binet (\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})\b/.exec(line);
    if (match) out.push(match[1]);
  }
  return out;
}

/** `wg show <if> peers` output to the list of public keys. */
export function parsePeers(output: string): string[] {
  return output.split('\n').map((l) => l.trim()).filter((l) => WG_KEY.test(l));
}

export interface Captured {
  code: number;
  stdout: string;
  stderr: string;
}
export type Capture = (argv: string[], stdin?: string) => Promise<Captured>;

export const denoCapture: Capture = async (argv, stdin) => {
  const child = new Deno.Command(argv[0], {
    args: argv.slice(1),
    stdin: stdin === undefined ? 'null' : 'piped',
    stdout: 'piped',
    stderr: 'piped',
  }).spawn();
  if (stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(stdin));
    await writer.close();
  }
  const output = await child.output();
  return {
    code: output.code,
    stdout: new TextDecoder().decode(output.stdout).slice(0, 65536),
    stderr: new TextDecoder().decode(output.stderr).slice(0, 500),
  };
};

/** Private key storage (a 0600 file; tests use memory). */
export interface KeyStore {
  /** Path handed to `wg set private-key`. */
  readonly path: string;
  read(): Promise<string | null>;
  /** Writes a new key; never overwrites an existing one. */
  create(key: string): Promise<void>;
}

export class FileKeyStore implements KeyStore {
  constructor(readonly path = MGMT_KEY_FILE) {}

  async read(): Promise<string | null> {
    try {
      const info = await Deno.lstat(this.path);
      if (!info.isFile || info.isSymlink || ((info.mode ?? 0) & 0o077) !== 0) {
        throw new Error('Unsafe management VPN key file');
      }
      return (await Deno.readTextFile(this.path)).trim();
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) return null;
      throw error;
    }
  }

  async create(key: string) {
    await Deno.writeTextFile(this.path, key + '\n', { mode: 0o600, createNew: true });
  }
}

export interface MgmtVpnApi {
  mgmtVpn(): Promise<unknown>;
  mgmtVpnKey(publicKey: string): Promise<void>;
}

export interface MgmtVpnOptions {
  api: MgmtVpnApi;
  run: Runner;
  capture: Capture;
  keys: KeyStore;
  log(message: string): void;
}

/**
 * Keeps `mnsagw-mgmt` and the host nft range set in sync with the control plane. Failures never
 * throw out of the timer: they are logged (once per distinct message), `status.error` holds the
 * last one, and the next cycle retries. Sessions that need the VPN fail with `mgmt_vpn_unavailable`.
 */
export class MgmtVpn implements MgmtGate {
  /** Last applied desired state (null: no hub, interface absent). */
  #applied: MgmtVpnDesired | null = null;
  #nftNet: string | null = null;
  #reportedKey: string | null = null;
  #chain: Promise<unknown> = Promise.resolve();
  #timer: ReturnType<typeof setInterval> | null = null;
  #lastError = '';
  error: string | null = null;

  constructor(private readonly options: MgmtVpnOptions) {}

  /** Range for `renderHostNft` after the host table is rebuilt (keeps the set in step). */
  get mgmtNet(): string | null {
    return this.#applied?.hub.mgmtNet ?? null;
  }

  /** The host table was (re)built with `mgmtNet`: the nft set is in step with it. */
  markNftApplied(mgmtNet: string | null) {
    this.#nftNet = mgmtNet;
  }

  start(intervalMs = MGMT_SYNC_MS) {
    void this.sync();
    this.#timer = setInterval(() => void this.sync(), intervalMs);
  }

  stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  /** One synchronisation (serialised); resolves to false when it failed (error in `error`). */
  sync(): Promise<boolean> {
    const next = this.#chain.then(() => this.#sync());
    this.#chain = next.catch(() => {});
    return next;
  }

  async require(hubUUID: string, destination: string, source: string): Promise<void> {
    if (!this.#ready(hubUUID, source)) await this.sync();
    const reason = this.#unavailable(hubUUID, destination, source);
    if (reason) {
      this.options.log(`management VPN not usable: ${reason}`);
      throw new MgmtVpnUnavailable();
    }
  }

  #ready(hubUUID: string, source: string) {
    const applied = this.#applied;
    return !!applied && applied.hub.uuid === hubUUID && applied.sources.includes(source);
  }

  #unavailable(hubUUID: string, destination: string, source: string): string | null {
    const applied = this.#applied;
    if (!applied) return 'no hub configured';
    if (applied.hub.uuid !== hubUUID) return 'hub differs from the assignment';
    const address = parseAddress(destination);
    const range = parseCidr(applied.hub.mgmtNet);
    if (!address || !range || !cidrContains(range, address)) return 'destination outside mgmtNet';
    if (!applied.sources.includes(source)) return 'source is not on the interface';
    if (this.#nftNet !== applied.hub.mgmtNet) return 'host firewall range not applied';
    return null;
  }

  async #must(argv: string[], stdin?: string) {
    const result = await this.options.run(argv, stdin);
    if (result.code !== 0) {
      throw new Error(`${argv.slice(0, 3).join(' ')} failed: ${result.stderr.trim()}`);
    }
  }

  async #capture(argv: string[], stdin?: string) {
    const result = await this.options.capture(argv, stdin);
    if (result.code !== 0) {
      throw new Error(`${argv.slice(0, 3).join(' ')} failed: ${result.stderr.trim()}`);
    }
    return result.stdout;
  }

  /** Generates the key on first use; returns the public key. */
  async #publicKey(): Promise<string> {
    let key = await this.options.keys.read();
    if (!key) {
      key = (await this.#capture(['wg', 'genkey'])).trim();
      if (!WG_KEY.test(key)) throw new Error('wg genkey returned an invalid key');
      await this.options.keys.create(key);
    }
    if (!WG_KEY.test(key)) throw new Error('management VPN key file is invalid');
    const pub = (await this.#capture(['wg', 'pubkey'], key + '\n')).trim();
    if (!WG_KEY.test(pub)) throw new Error('wg pubkey returned an invalid key');
    return pub;
  }

  async #read(): Promise<InterfaceState> {
    const link = await this.options.capture(['ip', 'link', 'show', 'dev', MGMT_IF]);
    if (link.code !== 0) {
      return { exists: false, addresses: [], peers: [] };
    }
    const addresses = parseAddresses(
      await this.#capture(['ip', '-o', '-4', 'addr', 'show', 'dev', MGMT_IF]),
    );
    const peers = parsePeers(await this.#capture(['wg', 'show', MGMT_IF, 'peers']));
    return { exists: true, addresses, peers };
  }

  async #setNft(mgmtNet: string | null) {
    if (this.#nftNet === mgmtNet) return;
    await this.#must(['nft', '-f', '-'], renderMgmtNetNft(mgmtNet));
    this.#nftNet = mgmtNet;
  }

  async #sync(): Promise<boolean> {
    try {
      const pub = await this.#publicKey();
      if (pub !== this.#reportedKey) {
        await this.options.api.mgmtVpnKey(pub);
        this.#reportedKey = pub;
      }
      const desired = parseMgmtVpn(await this.options.api.mgmtVpn());
      if (!desired) {
        // Close the firewall range first, then remove the interface.
        await this.#setNft(null);
        const state = await this.#read();
        if (state.exists) { for (const argv of renderMgmtVpnRemove()) await this.#must(argv); }
        this.#applied = null;
      } else {
        const state = await this.#read();
        for (const argv of renderMgmtVpnApply(desired, state, this.options.keys.path)) {
          await this.#must(argv);
        }
        const old = this.#applied?.hub.mgmtNet;
        if (old && old !== desired.hub.mgmtNet) {
          await this.options.run(['ip', 'route', 'del', old, 'dev', MGMT_IF]).catch(() => {});
        }
        this.#applied = desired;
        await this.#setNft(desired.hub.mgmtNet);
      }
      this.error = null;
      this.#lastError = '';
      return true;
    } catch (error) {
      const message = (error as Error).message.slice(0, 300);
      this.error = message;
      if (message !== this.#lastError) {
        this.#lastError = message;
        this.options.log(`management VPN sync failed: ${message}`);
      }
      return false;
    }
  }
}
