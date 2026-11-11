// Per-session worker sandbox: a transient systemd service in the session network namespace,
// with a dynamic user, no capabilities, no new privileges, a read-only system, limited memory,
// CPU and lifetime, a cgroup IP filter for the single device address, and Deno permissions that
// allow only the device IP:port (third layer after the namespace and host firewalls).

import { parseAddress } from '../shared/ip.ts';
import type { SessionNet, SessionTarget } from './netns.ts';

export const UNIT_PREFIX = 'mnscloud-access-gateway-session-';
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

/** Deno command line of the worker (also used without systemd by the tests). */
export function workerDenoArgs(
  runtimeRoot: string,
  target: SessionTarget,
  memoryMaxMB = 256,
): string[] {
  return [
    'run',
    '--cached-only',
    '--frozen',
    '--no-prompt',
    `--config=${runtimeRoot}/deno.json`,
    `--v8-flags=--max-old-space-size=${Math.max(64, Math.floor(memoryMaxMB * 0.6))}`,
    `--allow-net=${allowNet(target)}`,
    `--allow-read=${runtimeRoot}`,
    `${runtimeRoot}/src/worker/main.ts`,
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
  const properties = [
    `NetworkNamespacePath=/run/netns/${net.namespace}`,
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
    `RestrictAddressFamilies=${family}`,
    'RestrictNamespaces=yes',
    'RestrictRealtime=yes',
    'RestrictSUIDSGID=yes',
    'LockPersonality=yes',
    'SystemCallArchitectures=native',
    'SystemCallFilter=@system-service',
    // V8 uses memory protection keys (pkey_*), outside @system-service.
    'SystemCallFilter=pkey_alloc pkey_free pkey_mprotect',
    'SystemCallFilter=~@privileged @mount @swap @reboot @module @raw-io @debug @cpu-emulation @obsolete',
    `IPAddressAllow=${parsed.text}`,
    'IPAddressDeny=any',
    'InaccessiblePaths=-/etc/mnscloud -/var/lib/mnscloud -/root -/run/netns',
    'UMask=0077',
    'KeyringMode=private',
    'Environment=DENO_DIR=/tmp/deno',
    'Environment=DENO_NO_UPDATE_CHECK=1',
    'Environment=NO_COLOR=1',
    `WorkingDirectory=${runtimeRoot}`,
  ];
  return [
    'systemd-run',
    '--quiet',
    '--collect',
    '--pipe',
    '--wait',
    '--service-type=exec',
    `--unit=${unitName(net)}`,
    '--description=MNSCloud access gateway session',
    ...properties.flatMap((property) => ['-p', property]),
    '--',
    DENO_BIN,
    ...workerDenoArgs(runtimeRoot, target, limits.memoryMaxMB),
  ];
}
