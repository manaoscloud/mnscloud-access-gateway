// Per-session worker sandbox: a transient systemd service in the session network namespace,
// with a dynamic user, no capabilities, no new privileges, a read-only system, limited memory,
// CPU and lifetime, a cgroup IP filter for the single device address, and Deno permissions that
// allow only the device IP:port (third layer after the namespace and host firewalls).

import { parseAddress } from '../shared/ip.ts';
import { validBridgePath } from '../shared/ipc.ts';
import type { SessionNet, SessionTarget } from './netns.ts';

export const UNIT_PREFIX = 'mnscloud-access-gateway-session-';
/** Where the bridge socket appears inside a connector worker's unit (the real name stays hidden). */
export const BRIDGE_IN_UNIT = '/run/bridge.sock';
export const DENO_BIN = '/usr/local/bin/deno';

export interface SandboxLimits {
  memoryMaxMB: number;
  cpuQuotaPercent: number;
  tasksMax: number;
  maxSessionSeconds: number;
}

export const DEFAULT_SANDBOX: Omit<SandboxLimits, 'maxSessionSeconds'> = {
  memoryMaxMB: 256,
  cpuQuotaPercent: 50,
  tasksMax: 64,
};

export function unitName(net: Pick<SessionNet, 'id'>): string {
  return `${UNIT_PREFIX}${net.id}`;
}

/** `--allow-net` value for one address (IPv6 literals are bracketed). */
export function allowNet(target: SessionTarget): string {
  const parsed = parseAddress(target.address);
  if (!parsed) throw new Error('Invalid target address');
  const host = parsed.family === 6 ? `[${parsed.text}]` : parsed.text;
  return `${host}:${target.port}`;
}

/** True for Deno >= 2.9, which requires `--allow-net=unix:<path>` to open a unix socket. */
export function unixSocketNeedsNet(version: string): boolean {
  const [major, minor] = version.split('.').map(Number);
  return major > 2 || (major === 2 && minor >= 9);
}

/** Deno command line of the worker (also used without systemd by the tests). */
export function workerDenoArgs(
  runtimeRoot: string,
  target: SessionTarget,
  memoryMaxMB = 256,
  bridge: string | null = null,
  denoVersion: string = Deno.version.deno,
): string[] {
  // Connector transport: no TCP/UDP permission at all, only the one unix socket of the controller
  // bridge. Deno 2.8 (pinned by the runtime kit) grants it through read/write alone and rejects a
  // `unix:` net value; from 2.9 the same socket also needs a net grant for exactly that path.
  const access = bridge
    ? [
      ...(unixSocketNeedsNet(denoVersion) ? [`--allow-net=unix:${bridge}`] : []),
      `--allow-read=${runtimeRoot},${bridge}`,
      `--allow-write=${bridge}`,
    ]
    : [`--allow-net=${allowNet(target)}`, `--allow-read=${runtimeRoot}`];
  return [
    'run',
    '--cached-only',
    '--frozen',
    '--no-prompt',
    `--config=${runtimeRoot}/deno.json`,
    `--v8-flags=--max-old-space-size=${Math.max(64, Math.floor(memoryMaxMB * 0.6))}`,
    ...access,
    `${runtimeRoot}/src/worker/main.ts`,
  ];
}

/** Hardening shared by direct and connector workers (network properties are added by the caller). */
function sandboxProperties(runtimeRoot: string, limits: SandboxLimits): string[] {
  return [
    'DynamicUser=yes',
    `MemoryMax=${limits.memoryMaxMB}M`,
    'MemorySwapMax=0',
    `CPUQuota=${limits.cpuQuotaPercent}%`,
    `TasksMax=${limits.tasksMax}`,
    `RuntimeMaxSec=${Math.max(60, Math.floor(limits.maxSessionSeconds) + 30)}`,
    'NoNewPrivileges=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    'PrivateTmp=yes',
    'PrivateDevices=yes',
    'PrivateIPC=yes',
    'ProtectKernelTunables=yes',
    'ProtectKernelModules=yes',
    'ProtectKernelLogs=yes',
    'ProtectControlGroups=yes',
    'ProtectClock=yes',
    'ProtectHostname=yes',
    'ProtectProc=invisible',
    'ProcSubset=pid',
    'CapabilityBoundingSet=',
    'AmbientCapabilities=',
    'RestrictNamespaces=yes',
    'RestrictRealtime=yes',
    'RestrictSUIDSGID=yes',
    'LockPersonality=yes',
    'SystemCallArchitectures=native',
    'SystemCallFilter=@system-service',
    // V8 uses memory protection keys (pkey_*), outside @system-service.
    'SystemCallFilter=pkey_alloc pkey_free pkey_mprotect',
    'SystemCallFilter=~@privileged @mount @swap @reboot @module @raw-io @debug @cpu-emulation @obsolete',
    'IPAddressDeny=any',
    'InaccessiblePaths=-/etc/mnscloud -/var/lib/mnscloud -/root -/run/netns',
    'UMask=0077',
    'KeyringMode=private',
    'Environment=DENO_DIR=/tmp/deno',
    'Environment=DENO_NO_UPDATE_CHECK=1',
    'Environment=NO_COLOR=1',
    `WorkingDirectory=${runtimeRoot}`,
  ];
}

function systemdRun(unit: string, properties: string[], denoArgs: string[]): string[] {
  return [
    'systemd-run',
    '--quiet',
    '--collect',
    '--pipe',
    '--wait',
    '--service-type=exec',
    `--unit=${unit}`,
    '--description=MNSCloud access gateway session',
    ...properties.flatMap((property) => ['-p', property]),
    '--',
    DENO_BIN,
    ...denoArgs,
  ];
}

/** systemd-run argv of one session worker. stdin/stdout are piped straight to the worker. */
export function renderSystemdRun(
  net: SessionNet,
  target: SessionTarget,
  runtimeRoot: string,
  limits: SandboxLimits,
): string[] {
  const parsed = parseAddress(target.address);
  if (!parsed) throw new Error('Invalid target address');
  const family = parsed.family === 4 ? 'AF_INET' : 'AF_INET6';
  return systemdRun(unitName(net), [
    `NetworkNamespacePath=/run/netns/${net.namespace}`,
    `RestrictAddressFamilies=${family}`,
    `IPAddressAllow=${parsed.text}`,
    ...sandboxProperties(runtimeRoot, limits),
  ], workerDenoArgs(runtimeRoot, target, limits.memoryMaxMB));
}

/**
 * systemd-run argv of a connector-session worker: no network at all (private empty namespace,
 * AF_UNIX only, nothing allowed by the cgroup IP filter, no Deno net permission). The one thing it
 * can open is the controller's bridge socket.
 */
export function renderConnectorSystemdRun(
  id: string,
  target: SessionTarget,
  runtimeRoot: string,
  limits: SandboxLimits,
  bridge: string,
): string[] {
  if (!/^[0-9a-f]{8}$/.test(id)) throw new Error('Invalid session id');
  if (!validBridgePath(bridge)) throw new Error('Invalid bridge path');
  // /run is replaced by an empty tmpfs: the worker sees neither D-Bus, journald, systemd's transient
  // unit files nor other sessions' bridges. Only its own socket is bound in, under a fixed name, so
  // neither argv nor unit properties readable from inside carry the real path.
  return systemdRun(`${UNIT_PREFIX}${id}`, [
    'PrivateNetwork=yes',
    'RestrictAddressFamilies=AF_UNIX',
    'TemporaryFileSystem=/run:ro',
    `BindPaths=${bridge}:${BRIDGE_IN_UNIT}`,
    'InaccessiblePaths=-/run/dbus -/run/systemd',
    ...sandboxProperties(runtimeRoot, limits),
  ], workerDenoArgs(runtimeRoot, target, limits.memoryMaxMB, BRIDGE_IN_UNIT));
}
