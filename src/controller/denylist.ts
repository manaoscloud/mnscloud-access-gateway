// Destinations a support session may never reach through the public path (assessment 7.1 A2).
// Built-in special-purpose ranges plus the platform ranges the API sends in /config (DEV/PROD
// networks, management VPN ranges, MNSCloud public blocks). The API validates the destination
// at registration and on every connection; the gateway checks again and the host firewall drops
// these ranges on the forward path, so a bug in one layer does not open the platform.

import { type Cidr, cidrContains, parseAddress, parseCidr } from '../shared/ip.ts';

export const BUILTIN_DENY_IPV4 = [
  '0.0.0.0/8', // "this" network
  '10.0.0.0/8', // RFC 1918
  '100.64.0.0/10', // RFC 6598 shared address space (CGNAT)
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local, includes 169.254.169.254 cloud metadata
  '172.16.0.0/12', // RFC 1918
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // TEST-NET-1
  '192.88.99.0/24', // 6to4 relay anycast
  '192.168.0.0/16', // RFC 1918
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes broadcast
];

export const BUILTIN_DENY_IPV6 = [
  '::/127', // unspecified and loopback
  '::ffff:0:0/96', // IPv4-mapped (would reach IPv4 ranges)
  '64:ff9b::/96', // NAT64 well-known prefix (would reach IPv4 ranges)
  '64:ff9b:1::/48', // local-use NAT64
  '100::/64', // discard-only
  '2001::/32', // Teredo
  '2001:2::/48', // benchmarking
  '2001:10::/28', // ORCHID
  '2001:20::/28', // ORCHIDv2
  '2001:db8::/32', // documentation
  '2002::/16', // 6to4 (embeds IPv4)
  'fc00::/7', // unique local
  'fe80::/10', // link-local
  'fec0::/10', // site-local (deprecated)
  'ff00::/8', // multicast
];

export interface Denylist {
  deny: Cidr[];
  lab: Cidr[];
}

function parseList(values: unknown, label: string): Cidr[] {
  if (!Array.isArray(values)) return [];
  return values.map((value) => {
    const cidr = parseCidr(value);
    if (!cidr) throw new Error(`Invalid ${label} range`);
    return cidr;
  });
}

/**
 * Builds the effective list. DEV lab targets (`labTargets`, single hosts only) are honored only in
 * the development environment; production never has exceptions.
 */
export function buildDenylist(config: {
  environment: string;
  denylist?: unknown;
  labTargets?: unknown;
}): Denylist {
  const deny = [
    ...BUILTIN_DENY_IPV4.map((c) => parseCidr(c)!),
    ...BUILTIN_DENY_IPV6.map((c) => parseCidr(c)!),
    ...parseList(config.denylist, 'denylist'),
  ];
  const lab = config.environment === 'development'
    ? parseList(config.labTargets, 'lab target')
    : [];
  for (const cidr of lab) {
    if (cidr.prefix !== (cidr.family === 4 ? 32 : 128)) {
      throw new Error('Lab targets must be single hosts');
    }
  }
  return { deny, lab };
}

export type DestinationVerdict = { allowed: true; lab: boolean } | {
  allowed: false;
  range: string;
};

export function checkDestination(address: string, list: Denylist): DestinationVerdict {
  const parsed = parseAddress(address);
  if (!parsed) return { allowed: false, range: 'invalid' };
  if (list.lab.some((cidr) => cidrContains(cidr, parsed))) return { allowed: true, lab: true };
  const hit = list.deny.find((cidr) => cidrContains(cidr, parsed));
  return hit ? { allowed: false, range: hit.text } : { allowed: true, lab: false };
}
