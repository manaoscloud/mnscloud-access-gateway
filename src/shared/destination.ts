// Destination rules of the connector path (shared by the gateway and the connector; the API
// applies the same rules). Tenant private ranges are the point of a connector, so unlike the
// public path there is no private-range denylist. Always refused: loopback, link-local (including
// 169.254.169.254), multicast, unspecified, broadcast, IPv4-mapped/NAT64 forms and (connector
// only) the connector host's own addresses. A tenant `allowedCidrs` list narrows it further.

import { type Cidr, cidrContains, formatAddress, parseAddress, parseCidr } from './ip.ts';

const ALWAYS_REFUSED = [
  '0.0.0.0/8', // "this" network, unspecified
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local, cloud metadata
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes 255.255.255.255
  '::/127', // unspecified, loopback
  '::ffff:0:0/96', // IPv4-mapped
  '64:ff9b::/96', // NAT64
  'fe80::/10', // link-local
  'ff00::/8', // multicast
].map((text) => parseCidr(text)!);

/** Ports the remote support never uses (Telnet is out of scope; plain RouterOS API is clear text). */
export const REFUSED_PORTS = [23, 8728];

export type DestinationRefusal =
  | 'invalid_address'
  | 'invalid_port'
  | 'protocol_refused'
  | 'destination_refused'
  | 'not_allowed';

export interface DestinationPolicy {
  /** Tenant `allowedCidrs`; empty means every private destination outside the refused set. */
  allowedCidrs: Cidr[];
  /** Addresses of the connector host (never dialed). */
  ownAddresses?: string[];
}

export function parseAllowedCidrs(values: unknown): Cidr[] | null {
  if (values === undefined || values === null) return [];
  if (!Array.isArray(values) || values.length > 64) return null;
  const out: Cidr[] = [];
  for (const value of values) {
    const cidr = parseCidr(value);
    if (!cidr) return null;
    out.push(cidr);
  }
  return out;
}

/** Returns null when the destination may be dialed, otherwise the refusal code. */
export function checkConnectorDestination(
  host: unknown,
  port: unknown,
  policy: DestinationPolicy,
): DestinationRefusal | null {
  const address = parseAddress(host);
  if (!address) return 'invalid_address';
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    return 'invalid_port';
  }
  if (REFUSED_PORTS.includes(port as number)) return 'protocol_refused';
  if (ALWAYS_REFUSED.some((cidr) => cidrContains(cidr, address))) return 'destination_refused';
  for (const own of policy.ownAddresses ?? []) {
    const parsed = parseAddress(own);
    if (parsed && parsed.family === address.family && parsed.value === address.value) {
      return 'destination_refused';
    }
  }
  if (
    policy.allowedCidrs.length > 0 && !policy.allowedCidrs.some((c) => cidrContains(c, address))
  ) {
    return 'not_allowed';
  }
  return null;
}

/** Interface addresses plus the directed broadcast address of each IPv4 subnet. */
export function ownAddressesOf(
  interfaces: { address: string; netmask?: string; family: string; cidr?: string | null }[],
): string[] {
  const out = new Set<string>();
  for (const item of interfaces) {
    const address = parseAddress(item.address.split('%')[0]);
    if (!address) continue;
    out.add(address.text);
    if (address.family === 4 && item.cidr) {
      const prefix = Number(item.cidr.split('/')[1]);
      if (Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
        const host = (1n << BigInt(32 - prefix)) - 1n;
        out.add(formatAddress(4, address.value | host));
      }
    }
  }
  return [...out];
}

/** Addresses worth reporting in the heartbeat (informational): no loopback, link-local, max 16. */
export function reportedAddresses(
  interfaces: { address: string }[],
): string[] {
  const out: string[] = [];
  for (const item of interfaces) {
    const address = parseAddress(item.address.split('%')[0]);
    if (!address || ALWAYS_REFUSED.some((cidr) => cidrContains(cidr, address))) continue;
    if (!out.includes(address.text)) out.push(address.text);
    if (out.length >= 16) break;
  }
  return out;
}
