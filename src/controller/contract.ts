// JSON contract of `/api/v1/access/runtime/*` as the gateway reads it (docs/runtime-api.md).
// Everything received is validated here; an invalid assignment is refused, never "fixed".

import { parseAddress, parseCidr } from '../shared/ip.ts';
import type { ShellDialect, SupportLevel } from '../shared/ipc.ts';
import { DIALECTS } from '../worker/rules.ts';

export interface GatewayConfig {
  gatewayUUID: string;
  gatewayKey: string;
  environment: 'development' | 'production';
  listen: { address: string; port: number };
  edgeSources: string[];
  denylist: string[];
  labTargets: string[];
  sessionNetwork: { ipv4: string; ipv6: string };
  capacity: { maxSessions: number };
  openvault: { address: string; caCertificatePem: string | null };
  sandbox: { memoryMaxMB: number; cpuQuotaPercent: number; tasksMax: number };
  configDigest: string;
}

export interface Assignment {
  connectionUUID: string;
  mode: 'console' | 'test';
  protocol: 'ssh' | 'routeros_api';
  path: 'public';
  target: { address: string; port: number };
  shellDialect: ShellDialect;
  username: string;
  level: SupportLevel;
  hostKey: { pinned: string | null };
  tls: { pinned: string | null };
  ticket: { sha256: string; expiresAt: string } | null;
  terminal: { cols: number; rows: number };
  limits: {
    maxSessionSeconds: number;
    idleSeconds: number;
    maxOutputBytesPerSecond: number;
    maxOutputBytes: number;
  };
  recording: { enabled: boolean; partBytes: number; partSeconds: number };
}

export interface AssignmentsResponse {
  cursor: string;
  assignments: unknown[];
  cancelled: string[];
}

export interface CredentialResponse {
  credentialUseUUID: string;
  wrapToken: string;
  ttlSeconds: number;
}

export interface HostKeyResponse {
  decision: 'accept' | 'block';
  pinned: boolean;
}

export interface FinishBody {
  state: 'closed' | 'failed' | 'refused' | 'expired';
  reason: string;
  bytesFromDevice: number;
  bytesToDevice: number;
  durationMs: number;
  recording: { parts: number; bytes: number; sha256: string } | null;
  facts: Record<string, string> | null;
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PIN = /^SHA256:[A-Za-z0-9+/]{43}$/;
const KEY = /^[a-z0-9][a-z0-9-]{1,62}$/;

export class ContractError extends Error {}

function int(value: unknown, min: number, max: number, label: string): number {
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new ContractError(`Invalid ${label}`);
  }
  return value as number;
}

function pin(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !PIN.test(value)) throw new ContractError('Invalid pin');
  return value;
}

function strings(value: unknown, label: string, check: (v: string) => boolean): string[] {
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) || value.length > 4096 ||
    !value.every((v) => typeof v === 'string' && check(v))
  ) {
    throw new ContractError(`Invalid ${label}`);
  }
  return value as string[];
}

export function parseConfig(value: unknown): GatewayConfig {
  // deno-lint-ignore no-explicit-any
  const v = value as Record<string, any>;
  if (!v || typeof v !== 'object') throw new ContractError('Invalid configuration');
  if (!UUID.test(String(v.gatewayUUID))) throw new ContractError('Invalid gatewayUUID');
  if (!KEY.test(String(v.gatewayKey))) throw new ContractError('Invalid gatewayKey');
  if (v.environment !== 'development' && v.environment !== 'production') {
    throw new ContractError('Invalid environment');
  }
  const listenAddress = parseAddress(v.listen?.address);
  if (!listenAddress) throw new ContractError('Invalid listen address');
  const openvault = String(v.openvault?.address ?? '');
  let vaultUrl: URL;
  try {
    vaultUrl = new URL(openvault);
  } catch {
    throw new ContractError('Invalid OpenVault address');
  }
  if (
    vaultUrl.protocol !== 'https:' || vaultUrl.pathname !== '/' || vaultUrl.search ||
    vaultUrl.username
  ) {
    throw new ContractError('Invalid OpenVault address');
  }
  const ca = v.openvault?.caCertificatePem ?? null;
  if (
    ca !== null &&
    (typeof ca !== 'string' || !ca.includes('BEGIN CERTIFICATE') || ca.length > 65536)
  ) {
    throw new ContractError('Invalid OpenVault CA');
  }
  const isCidr = (c: string) => parseCidr(c) !== null;
  return {
    gatewayUUID: v.gatewayUUID,
    gatewayKey: v.gatewayKey,
    environment: v.environment,
    listen: {
      address: listenAddress.text,
      port: int(v.listen?.port ?? 7443, 1024, 65535, 'listen port'),
    },
    edgeSources: strings(v.edgeSources, 'edgeSources', isCidr),
    denylist: strings(v.denylist, 'denylist', isCidr),
    labTargets: v.environment === 'development' ? strings(v.labTargets, 'labTargets', isCidr) : [],
    sessionNetwork: {
      ipv4: typeof v.sessionNetwork?.ipv4 === 'string' ? v.sessionNetwork.ipv4 : '100.127.192.0/18',
      ipv6: typeof v.sessionNetwork?.ipv6 === 'string'
        ? v.sessionNetwork.ipv6
        : 'fd6d:6e73:6177::/48',
    },
    capacity: { maxSessions: int(v.capacity?.maxSessions ?? 32, 1, 512, 'capacity') },
    openvault: { address: vaultUrl.origin, caCertificatePem: ca },
    sandbox: {
      memoryMaxMB: int(v.sandbox?.memoryMaxMB ?? 256, 128, 2048, 'memoryMaxMB'),
      cpuQuotaPercent: int(v.sandbox?.cpuQuotaPercent ?? 50, 5, 400, 'cpuQuotaPercent'),
      tasksMax: int(v.sandbox?.tasksMax ?? 64, 16, 512, 'tasksMax'),
    },
    configDigest: typeof v.configDigest === 'string' ? v.configDigest.slice(0, 128) : '',
  };
}

export function parseAssignment(value: unknown): Assignment {
  // deno-lint-ignore no-explicit-any
  const v = value as Record<string, any>;
  if (!v || typeof v !== 'object') throw new ContractError('Invalid assignment');
  if (!UUID.test(String(v.connectionUUID))) throw new ContractError('Invalid connectionUUID');
  if (v.mode !== 'console' && v.mode !== 'test') throw new ContractError('Invalid mode');
  if (v.protocol !== 'ssh' && v.protocol !== 'routeros_api') {
    throw new ContractError('protocol_refused');
  }
  if ((v.path ?? 'public') !== 'public') throw new ContractError('path_unsupported');
  const address = parseAddress(v.target?.address);
  if (!address) throw new ContractError('Invalid target address');
  if (!DIALECTS.includes(v.shellDialect)) throw new ContractError('Invalid shellDialect');
  if (
    typeof v.username !== 'string' || !v.username || v.username.length > 128 ||
    /[\r\n\0]/.test(v.username)
  ) {
    throw new ContractError('Invalid username');
  }
  if (!['n1', 'n2', 'n3'].includes(v.level)) throw new ContractError('Invalid level');
  let ticket: Assignment['ticket'] = null;
  if (v.mode === 'console') {
    if (
      !/^[0-9a-f]{64}$/.test(String(v.ticket?.sha256)) ||
      Number.isNaN(Date.parse(String(v.ticket?.expiresAt)))
    ) {
      throw new ContractError('Invalid ticket');
    }
    ticket = { sha256: v.ticket.sha256, expiresAt: v.ticket.expiresAt };
  }
  return {
    connectionUUID: v.connectionUUID,
    mode: v.mode,
    protocol: v.protocol,
    path: 'public',
    target: { address: address.text, port: int(v.target.port, 1, 65535, 'port') },
    shellDialect: v.shellDialect,
    username: v.username,
    level: v.level,
    hostKey: { pinned: pin(v.hostKey?.pinned) },
    tls: { pinned: pin(v.tls?.pinned) },
    ticket,
    terminal: {
      cols: int(v.terminal?.cols ?? 120, 20, 500, 'cols'),
      rows: int(v.terminal?.rows ?? 32, 5, 200, 'rows'),
    },
    limits: {
      maxSessionSeconds: int(v.limits?.maxSessionSeconds ?? 14400, 30, 86400, 'maxSessionSeconds'),
      idleSeconds: int(v.limits?.idleSeconds ?? 900, 30, 86400, 'idleSeconds'),
      maxOutputBytesPerSecond: int(
        v.limits?.maxOutputBytesPerSecond ?? 262144,
        4096,
        16777216,
        'output rate',
      ),
      maxOutputBytes: int(v.limits?.maxOutputBytes ?? 268435456, 65536, 4294967296, 'output limit'),
    },
    recording: {
      enabled: v.recording?.enabled !== false,
      partBytes: int(v.recording?.partBytes ?? 1048576, 65536, 8388608, 'partBytes'),
      partSeconds: int(v.recording?.partSeconds ?? 60, 5, 600, 'partSeconds'),
    },
  };
}
