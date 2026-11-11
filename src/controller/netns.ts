// Network isolation of a session (pure renderers + a privileged applier).
//
// Each session gets its own network namespace connected to the host by a veth pair. Inside the
// namespace nftables allows output only to the device IP:port (no DNS, nothing else). On the host
// the forward path drops every denylisted range before the per-session allow set is consulted,
// and the namespaces' traffic is masqueraded to the gateway's public egress address. Only the
// controller (root) runs `ip` and `nft`; the worker never has a capability to change them.

import {
  type Cidr,
  cidrOffset,
  type Family,
  formatAddress,
  parseAddress,
  parseCidr,
} from '../shared/ip.ts';
import type { Denylist } from './denylist.ts';

export const HOST_TABLE = 'mnscloud_access_gateway';
export const SESSION_TABLE = 'mnscloud_session';
export const NETNS_PREFIX = 'mnsagw-';
export const HOST_IF_PREFIX = 'agwh';
export const NS_IF_PREFIX = 'agwn';
export const DEFAULT_POOL_IPV4 = '100.127.192.0/18';
export const DEFAULT_POOL_IPV6 = 'fd6d:6e73:6177::/48';

export interface SessionNet {
  id: string; // 8 hex characters
  index: number;
  namespace: string;
  hostIf: string;
  nsIf: string;
  host4: string;
  ns4: string;
  host6: string;
  ns6: string;
}

export interface SessionTarget {
  address: string;
  port: number;
}

export function sessionId(connectionUUID: string): string {
  const hex = connectionUUID.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error('Invalid connection UUID');
  return hex.slice(0, 8);
}

/** Addressing of slot `index`: a /30 out of the IPv4 pool and a /64 out of the IPv6 pool. */
export function sessionNetwork(
  connectionUUID: string,
  index: number,
  pool4 = DEFAULT_POOL_IPV4,
  pool6 = DEFAULT_POOL_IPV6,
): SessionNet {
  const id = sessionId(connectionUUID);
  const v4 = parseCidr(pool4), v6 = parseCidr(pool6);
  if (!v4 || v4.family !== 4 || v4.prefix > 30) throw new Error('Invalid IPv4 session pool');
  if (!v6 || v6.family !== 6 || v6.prefix > 64) throw new Error('Invalid IPv6 session pool');
  if (!Number.isInteger(index) || index < 0 || index >= maxSlots(v4, v6)) {
    throw new Error('Session slot out of range');
  }
  const base4 = cidrOffset(v4, BigInt(index) * 4n);
  const base6 = v6.base + (BigInt(index) << 64n);
  return {
    id,
    index,
    namespace: `${NETNS_PREFIX}${id}`,
    hostIf: `${HOST_IF_PREFIX}${id}`,
    nsIf: `${NS_IF_PREFIX}${id}`,
    host4: formatAddress(4, base4 + 1n),
    ns4: formatAddress(4, base4 + 2n),
    host6: formatAddress(6, base6 + 1n),
    ns6: formatAddress(6, base6 + 2n),
  };
}

export function maxSlots(pool4: Cidr, pool6: Cidr): number {
  const slots4 = 2 ** (32 - pool4.prefix) / 4;
  const slots6 = 2 ** Math.min(30, 64 - pool6.prefix);
  return Math.min(slots4, slots6, 4096);
}

/** Commands (argv) that create the namespace and its link; run in order by the controller. */
export function renderNetnsSetup(net: SessionNet): string[][] {
  const ns = ['ip', 'netns', 'exec', net.namespace];
  return [
    ['ip', 'netns', 'add', net.namespace],
    [
      'ip',
      'link',
      'add',
      net.hostIf,
      'type',
      'veth',
      'peer',
      'name',
      net.nsIf,
      'netns',
      net.namespace,
    ],
    ['ip', 'addr', 'add', `${net.host4}/30`, 'dev', net.hostIf],
    ['ip', '-6', 'addr', 'add', `${net.host6}/64`, 'dev', net.hostIf, 'nodad'],
    ['ip', 'link', 'set', net.hostIf, 'up'],
    [...ns, 'ip', 'link', 'set', 'lo', 'up'],
    [...ns, 'ip', 'addr', 'add', `${net.ns4}/30`, 'dev', net.nsIf],
    [...ns, 'ip', '-6', 'addr', 'add', `${net.ns6}/64`, 'dev', net.nsIf, 'nodad'],
    [...ns, 'ip', 'link', 'set', net.nsIf, 'up'],
    [...ns, 'ip', 'route', 'add', 'default', 'via', net.host4],
    [...ns, 'ip', '-6', 'route', 'add', 'default', 'via', net.host6],
  ];
}

export function renderNetnsTeardown(net: SessionNet): string[][] {
  // Deleting the namespace removes its end of the veth pair, which removes the host end too.
  return [['ip', 'netns', 'delete', net.namespace], ['ip', 'link', 'delete', net.hostIf]];
}

function daddr(family: Family) {
  return family === 4 ? 'ip daddr' : 'ip6 daddr';
}

/** nftables ruleset inside the session namespace: output only to the device IP:port. */
export function renderSessionNft(target: SessionTarget): string {
  const address = parseAddress(target.address);
  if (!address) throw new Error('Invalid target address');
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    throw new Error('Invalid target port');
  }
  return [
    `table inet ${SESSION_TABLE} {`,
    '  chain output {',
    '    type filter hook output priority filter; policy drop;',
    '    oif "lo" accept',
    '    ct state established,related accept',
    `    ${daddr(address.family)} ${address.text} tcp dport ${target.port} ct state new accept`,
    '  }',
    '  chain input {',
    '    type filter hook input priority filter; policy drop;',
    '    iif "lo" accept',
    '    ct state established,related accept',
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter; policy drop;',
    '  }',
    '}',
    '',
  ].join('\n');
}

function elements(list: Cidr[], family: Family): string {
  const items = list.filter((c) => c.family === family).map((c) => c.text);
  return items.length ? ` elements = { ${items.join(', ')} };` : '';
}

export interface HostFirewallInput {
  denylist: Denylist;
  edgeSources: Cidr[];
  listenPort: number;
  pool4?: string;
  pool6?: string;
}

/**
 * Host table (replaced atomically). Forward path: established replies, then a DEV lab target of
 * an active session, then the denylist, then the per-session allow sets. The controller's own
 * listener accepts only the edge hosts.
 */
export function renderHostNft(input: HostFirewallInput): string {
  const pool4 = parseCidr(input.pool4 ?? DEFAULT_POOL_IPV4)!;
  const pool6 = parseCidr(input.pool6 ?? DEFAULT_POOL_IPV6)!;
  const t = HOST_TABLE;
  return [
    `table inet ${t} {}`,
    `delete table inet ${t}`,
    `table inet ${t} {`,
    `  set deny4 { type ipv4_addr; flags interval; auto-merge;${
      elements(input.denylist.deny, 4)
    } }`,
    `  set deny6 { type ipv6_addr; flags interval; auto-merge;${
      elements(input.denylist.deny, 6)
    } }`,
    `  set lab4 { type ipv4_addr; flags interval; auto-merge;${elements(input.denylist.lab, 4)} }`,
    `  set lab6 { type ipv6_addr; flags interval; auto-merge;${elements(input.denylist.lab, 6)} }`,
    `  set edge4 { type ipv4_addr; flags interval; auto-merge;${elements(input.edgeSources, 4)} }`,
    `  set edge6 { type ipv6_addr; flags interval; auto-merge;${elements(input.edgeSources, 6)} }`,
    '  set sessions4 { type ifname . ipv4_addr . inet_service; }',
    '  set sessions6 { type ifname . ipv6_addr . inet_service; }',
    '  chain input {',
    '    type filter hook input priority filter - 5; policy accept;',
    `    iifname "${HOST_IF_PREFIX}*" drop`,
    '    iif "lo" accept',
    `    tcp dport ${input.listenPort} ip saddr @edge4 accept`,
    `    tcp dport ${input.listenPort} ip6 saddr @edge6 accept`,
    `    tcp dport ${input.listenPort} drop`,
    '  }',
    '  chain forward {',
    '    type filter hook forward priority filter - 5; policy drop;',
    '    ct state established,related accept',
    '    ct state invalid drop',
    `    iifname != "${HOST_IF_PREFIX}*" drop`,
    '    meta l4proto != tcp drop',
    '    iifname . ip daddr . tcp dport @sessions4 ip daddr @lab4 accept',
    '    iifname . ip6 daddr . tcp dport @sessions6 ip6 daddr @lab6 accept',
    '    ip daddr @deny4 drop',
    '    ip6 daddr @deny6 drop',
    '    iifname . ip daddr . tcp dport @sessions4 accept',
    '    iifname . ip6 daddr . tcp dport @sessions6 accept',
    '  }',
    '  chain postrouting {',
    '    type nat hook postrouting priority srcnat; policy accept;',
    `    ip saddr ${pool4.text} oifname != "${HOST_IF_PREFIX}*" masquerade`,
    `    ip6 saddr ${pool6.text} oifname != "${HOST_IF_PREFIX}*" masquerade`,
    '  }',
    '}',
    '',
  ].join('\n');
}

/** nft commands that add / remove the session's single allowed destination on the host. */
export function renderHostSessionElement(
  net: SessionNet,
  target: SessionTarget,
  action: 'add' | 'delete',
): string {
  const address = parseAddress(target.address);
  if (!address) throw new Error('Invalid target address');
  const set = address.family === 4 ? 'sessions4' : 'sessions6';
  return `${action} element inet ${HOST_TABLE} ${set} { "${net.hostIf}" . ${address.text} . ${target.port} }\n`;
}

export type Runner = (argv: string[], stdin?: string) => Promise<{ code: number; stderr: string }>;

export const denoRunner: Runner = async (argv, stdin) => {
  const child = new Deno.Command(argv[0], {
    args: argv.slice(1),
    stdin: stdin === undefined ? 'null' : 'piped',
    stdout: 'null',
    stderr: 'piped',
  }).spawn();
  if (stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(stdin));
    await writer.close();
  }
  const output = await child.output();
  return { code: output.code, stderr: new TextDecoder().decode(output.stderr).slice(0, 500) };
};

/** Allocates slots and applies/removes session networks with the privileged runner. */
export class SessionNetworks {
  #used = new Set<number>();
  constructor(
    private readonly run: Runner,
    private readonly capacity: number,
    private readonly pool4 = DEFAULT_POOL_IPV4,
    private readonly pool6 = DEFAULT_POOL_IPV6,
  ) {}

  async create(connectionUUID: string, target: SessionTarget): Promise<SessionNet> {
    let index = 0;
    while (this.#used.has(index)) index++;
    if (index >= this.capacity) throw new Error('No free session slot');
    this.#used.add(index);
    const net = sessionNetwork(connectionUUID, index, this.pool4, this.pool6);
    try {
      for (const argv of renderNetnsSetup(net)) await this.#must(argv);
      await this.#must(
        ['ip', 'netns', 'exec', net.namespace, 'nft', '-f', '-'],
        renderSessionNft(target),
      );
      await this.#must(['nft', '-f', '-'], renderHostSessionElement(net, target, 'add'));
      return net;
    } catch (error) {
      await this.destroy(net, target);
      throw error;
    }
  }

  async destroy(net: SessionNet, target: SessionTarget) {
    await this.run(['nft', '-f', '-'], renderHostSessionElement(net, target, 'delete')).catch(
      () => {},
    );
    for (const argv of renderNetnsTeardown(net)) await this.run(argv).catch(() => {});
    this.#used.delete(net.index);
  }

  async #must(argv: string[], stdin?: string) {
    const result = await this.run(argv, stdin);
    if (result.code !== 0) throw new Error(`${argv.slice(0, 3).join(' ')} failed`);
  }
}
