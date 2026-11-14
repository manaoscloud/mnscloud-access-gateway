// JSON contract of `/api/v1/access/runtime/*` as the gateway reads it (docs/runtime-api.md).
// Everything received is validated here; an invalid assignment is refused, never "fixed".

import { parseAddress, parseCidr } from '../shared/ip.ts';
import { type ExecPayload, ExecPayloadError, parseExecPayload } from '../shared/exec.ts';
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
  mode: 'console' | 'test' | 'exec';
  protocol: 'ssh' | 'routeros_api';
  path: 'public' | 'connector' | 'mgmt_vpn';
  /**
   * `connector`: the worker has no network; the stream goes through the tenant connector.
   * `mgmt_vpn`: a direct session whose only way out is the management VPN interface, with the
   * owner's source address.
   */
  transport: 'direct' | 'connector' | 'mgmt_vpn';
  /** `mgmt_vpn` only: the hub it must be on and the source address of the owner; else null. */
  mgmtVpn: { hubUUID: string; source: string } | null;
  connectorUuid: string | null;
  /** Fingerprint of the connector key the API expects (`SHA256:` + base64); null for direct. */
  connectorKeyFingerprint: string | null;
  target: { address: string; port: number };
  shellDialect: ShellDialect;
  username: string;
  level: SupportLevel;
  hostKey: { pinned: string | null };
  tls: { pinned: string | null };
  ticket: { sha256: string; expiresAt: string } | null;
  /**
   * Console of a support session: a closed browser does not end the connection, a browser can
   * attach again later (attach tickets). False when the API does not send it.
   */
  detachable: boolean;
  /** `exec` mode only (AI copilot): the validated command payload; null otherwise. */
  exec: ExecPayload | null;
  terminal: { cols: number; rows: number };
  limits: {
    maxSessionSeconds: number;
    idleSeconds: number;
    maxOutputBytesPerSecond: number;
    maxOutputBytes: number;
  };
  recording: { enabled: boolean; partBytes: number; partSeconds: number };
}

/** Desired state of the management VPN interface (`GET /mgmt-vpn`). */
export interface MgmtVpnDesired {
  hub: {
    uuid: string;
    endpoint: string;
    publicKey: string;
    mgmtNet: string;
    gatewayNet: string;
  };
  sources: string[];
}

/** Extra single-use ticket to attach a browser to a live connection (support sessions). */
export interface AttachTicket {
  connectionUUID: string;
  sha256: string;
  expiresAt: string;
  role: 'operator' | 'observer';
}

export interface AssignmentsResponse {
  cursor: string;
  assignments: unknown[];
  cancelled: string[];
  /** Absent on an API that does not know support sessions. */
  attachTickets?: unknown[];
}

/** Valid attach tickets of a raw list; malformed items are skipped, never fixed. */
export function parseAttachTickets(value: unknown): AttachTicket[] {
  if (!Array.isArray(value)) return [];
  const out: AttachTicket[] = [];
  for (const item of value.slice(0, 256)) {
    const v = item as Record<string, unknown> | null;
    if (!v || typeof v !== 'object') continue;
    if (
      typeof v.connectionUUID !== 'string' || !UUID.test(v.connectionUUID) ||
      typeof v.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(v.sha256) ||
      typeof v.expiresAt !== 'string' || Number.isNaN(Date.parse(v.expiresAt)) ||
      (v.role !== 'operator' && v.role !== 'observer')
    ) continue;
    out.push({
      connectionUUID: v.connectionUUID,
      sha256: v.sha256,
      expiresAt: v.expiresAt,
      role: v.role,
    });
  }
  return out;
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

/** Raised for an exec assignment whose sha256 does not match its payload. */
export const EXEC_PAYLOAD_MISMATCH = 'EXEC_PAYLOAD_MISMATCH';

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

type Route = Pick<
  Assignment,
  'path' | 'transport' | 'connectorUuid' | 'connectorKeyFingerprint' | 'mgmtVpn'
>;

/** `mgmtVpn: { hubUUID, source }` of a management VPN assignment. */
function parseMgmtVpnRoute(value: unknown): { hubUUID: string; source: string } {
  if (!value || typeof value !== 'object') throw new ContractError('Invalid mgmtVpn hubUUID');
  const mgmt = value as Record<string, unknown>;
  const hubUUID = typeof mgmt.hubUUID === 'string' ? mgmt.hubUUID : '';
  if (!UUID.test(hubUUID)) throw new ContractError('Invalid mgmtVpn hubUUID');
  const source = parseAddress(mgmt.source);
  if (source?.family !== 4 || source.text !== mgmt.source) {
    throw new ContractError('Invalid mgmtVpn source');
  }
  return { hubUUID, source: source.text };
}

/** Path, transport and connector identity (a connector assignment pins the key it expects). */
function parseRoute(v: Record<string, unknown>): Route {
  const path = v.path ?? 'public';
  if (path !== 'public' && path !== 'connector' && path !== 'mgmt_vpn') {
    throw new ContractError('path_unsupported');
  }
  const transport = v.transport ?? (path === 'public' ? 'direct' : path);
  if (transport !== 'direct' && transport !== 'connector' && transport !== 'mgmt_vpn') {
    throw new ContractError('path_unsupported');
  }
  if ((path === 'connector') !== (transport === 'connector')) {
    throw new ContractError('path_unsupported');
  }
  if ((path === 'mgmt_vpn') !== (transport === 'mgmt_vpn')) {
    throw new ContractError('path_unsupported');
  }
  if (transport === 'direct') {
    return { path, transport, connectorUuid: null, connectorKeyFingerprint: null, mgmtVpn: null };
  }
  if (transport === 'mgmt_vpn') {
    return {
      path,
      transport,
      connectorUuid: null,
      connectorKeyFingerprint: null,
      mgmtVpn: parseMgmtVpnRoute(v.mgmtVpn),
    };
  }
  const connectorUuid = typeof v.connectorUuid === 'string' ? v.connectorUuid : '';
  const fingerprint = typeof v.connectorKeyFingerprint === 'string'
    ? v.connectorKeyFingerprint
    : '';
  if (!UUID.test(connectorUuid)) throw new ContractError('Invalid connectorUuid');
  if (!/^SHA256:[A-Za-z0-9+/]{43}=$/.test(fingerprint)) {
    throw new ContractError('Invalid connectorKeyFingerprint');
  }
  return { path, transport, connectorUuid, connectorKeyFingerprint: fingerprint, mgmtVpn: null };
}

// deno-lint-ignore no-explicit-any
function parseTicket(v: Record<string, any>): Assignment['ticket'] {
  if (v.mode !== 'console') return null;
  if (
    !/^[0-9a-f]{64}$/.test(String(v.ticket?.sha256)) ||
    Number.isNaN(Date.parse(String(v.ticket?.expiresAt)))
  ) {
    throw new ContractError('Invalid ticket');
  }
  return { sha256: v.ticket.sha256, expiresAt: v.ticket.expiresAt };
}

/** The `exec` payload: required (and only allowed) for mode exec. */
// deno-lint-ignore no-explicit-any
function parseExec(v: Record<string, any>, transport: Assignment['transport']): ExecPayload | null {
  if (v.mode !== 'exec') {
    if (v.exec !== undefined && v.exec !== null) throw new ContractError('Invalid exec');
    return null;
  }
  if (v.protocol !== 'ssh') throw new ContractError('protocol_refused');
  try {
    const exec = parseExecPayload(v.exec, v.shellDialect, v.connectionUUID);
    // A change verifies in a second SSH connection; the connector bridge carries only one.
    if (exec.kind === 'change' && transport === 'connector') {
      throw new ContractError('exec_change_unsupported_transport');
    }
    return exec;
  } catch (error) {
    if (error instanceof ExecPayloadError) {
      throw new ContractError(
        error.message === 'EXEC_PAYLOAD_MISMATCH' ? error.message : 'Invalid exec payload',
      );
    }
    throw error;
  }
}

export function parseAssignment(value: unknown): Assignment {
  // deno-lint-ignore no-explicit-any
  const v = value as Record<string, any>;
  if (!v || typeof v !== 'object') throw new ContractError('Invalid assignment');
  if (!UUID.test(String(v.connectionUUID))) throw new ContractError('Invalid connectionUUID');
  if (v.mode !== 'console' && v.mode !== 'test' && v.mode !== 'exec') {
    throw new ContractError('Invalid mode');
  }
  if (v.protocol !== 'ssh' && v.protocol !== 'routeros_api') {
    throw new ContractError('protocol_refused');
  }
  const route = parseRoute(v);
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
  if (route.transport === 'mgmt_vpn' && address.family !== 4) {
    throw new ContractError('Invalid target address');
  }
  const ticket = parseTicket(v);
  const exec = parseExec(v, route.transport);
  return {
    connectionUUID: v.connectionUUID,
    mode: v.mode,
    protocol: v.protocol,
    ...route,
    target: { address: address.text, port: int(v.target.port, 1, 65535, 'port') },
    shellDialect: v.shellDialect,
    username: v.username,
    level: v.level,
    hostKey: { pinned: pin(v.hostKey?.pinned) },
    tls: { pinned: pin(v.tls?.pinned) },
    ticket,
    detachable: v.mode === 'console' && v.detachable === true,
    exec,
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
      enabled: v.mode !== 'exec' && v.recording?.enabled !== false,
      partBytes: int(v.recording?.partBytes ?? 1048576, 65536, 8388608, 'partBytes'),
      partSeconds: int(v.recording?.partSeconds ?? 60, 5, 600, 'partSeconds'),
    },
  };
}
