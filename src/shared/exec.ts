// Exec mode (AI copilot, ST-F): payload validation shared by the controller (assignment) and the
// worker (init), and the result types. The payload is validated strictly and its sha256 is
// recomputed from the canonical JSON; a payload that does not match is refused, never fixed.

import { createHash } from 'node:crypto';

export type ExecKind = 'read' | 'change';
export type SafeChange = 'routeros_safe_mode' | 'vrp5_schedule_reboot' | 'systemd_deadman' | 'none';
export type ChangeLogKind = 'script' | 'file' | 'report_only';

export interface ExecPayload {
  kind: ExecKind;
  requestUUID: string;
  steps: string[];
  verify: string[];
  rollback: string[];
  safeChange: SafeChange;
  rollbackSeconds: number;
  backupName: string | null;
  changeLog: { kind: ChangeLogKind; line: string } | null;
  sha256: string;
}

export type ExecStatus = 'ok' | 'blocked' | 'failed' | 'applied' | 'rolled_back';
export type ExecPhase = 'system' | 'step' | 'verify' | 'rollback';

export interface ExecStepResult {
  phase: ExecPhase;
  command: string;
  class: string | null;
  rule: string | null;
  verdict: 'allowed' | 'blocked';
  exitCode: number | null;
  output: string;
  truncated: boolean;
  ms: number;
}

export interface ExecResult {
  status: ExecStatus;
  steps: ExecStepResult[];
  rollback: {
    method: 'safe_mode' | 'scheduled_reboot' | 'deadman_timer' | 'none';
    armed: boolean;
    fired: boolean;
    pendingReboot: boolean;
  };
  error: { code: string; message: string } | null;
}

export class ExecPayloadError extends Error {}

const MAX_COMMAND = 1000;
const SAFE_CHANGES = ['routeros_safe_mode', 'vrp5_schedule_reboot', 'systemd_deadman'];
const KEYS = [
  'kind',
  'requestUUID',
  'steps',
  'verify',
  'rollback',
  'safeChange',
  'rollbackSeconds',
  'backupName',
  'changeLog',
  'sha256',
];
const HEX32 = /^[0-9a-f]{32}$/i;
const UUID_FORM = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BACKUP = /^[a-z0-9-]{1,48}$/;
// Printable ASCII without quotes, backslash, `$`, backtick, `;`, `?` (inline help on RouterOS) and
// `[ ] { } | & < >` (the line is embedded in device commands).
const LOG_LINE = /^[ !#%()*+,\-./0-9:=@A-Z^_a-z~]{1,300}$/;

/** Lowercase hex of a request UUID in either form (32 hex or the dashed form). */
export function requestHex(value: string): string {
  return value.replace(/-/g, '').toLowerCase();
}

/** Canonical JSON the sha256 covers: keys in exactly this order. */
export function canonicalExec(p: ExecPayload): string {
  return JSON.stringify({
    kind: p.kind,
    steps: p.steps,
    verify: p.verify,
    rollback: p.rollback,
    safeChange: p.safeChange,
    rollbackSeconds: p.rollbackSeconds,
    backupName: p.backupName,
    changeLog: p.changeLog ? { kind: p.changeLog.kind, line: p.changeLog.line } : null,
  });
}

export function execSha256(p: ExecPayload): string {
  return createHash('sha256').update(canonicalExec(p)).digest('hex');
}

function commands(
  value: unknown,
  label: string,
  min: number,
  max: number,
  dialect: string,
): string[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    throw new ExecPayloadError(`Invalid exec ${label}`);
  }
  // Control characters (Tab included) could trigger completion or editing in a device shell, and
  // `?` is inline help on RouterOS and VRP.
  const inlineHelp = dialect === 'routeros' || dialect === 'vrp';
  for (const item of value) {
    if (
      typeof item !== 'string' || !item.trim() || item.length > MAX_COMMAND ||
      // deno-lint-ignore no-control-regex
      /[\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(item) || (inlineHelp && item.includes('?'))
    ) throw new ExecPayloadError(`Invalid exec ${label}`);
  }
  return value as string[];
}

const SAFE_FOR_DIALECT: Record<string, string[]> = {
  routeros: ['routeros_safe_mode'],
  vrp: ['vrp5_schedule_reboot'],
  linux: ['systemd_deadman'],
  proxmox: ['systemd_deadman'],
};

/**
 * Validates an `exec` payload for a device dialect. `connectionUUID` is the one the payload must
 * echo. Throws `ExecPayloadError('EXEC_PAYLOAD_MISMATCH')` when only the sha256 differs.
 */
export function parseExecPayload(
  value: unknown,
  dialect: string,
  connectionUUID: string,
): ExecPayload {
  // The `other` dialect has no safe prompt handling: exec is refused for it, read or change.
  if (!(dialect in SAFE_FOR_DIALECT)) throw new ExecPayloadError('Invalid exec dialect');
  const v = value as Record<string, unknown> | null;
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new ExecPayloadError('Invalid exec');
  if (Object.keys(v).some((key) => !KEYS.includes(key))) {
    throw new ExecPayloadError('Invalid exec field');
  }
  if (v.kind !== 'read' && v.kind !== 'change') throw new ExecPayloadError('Invalid exec kind');
  const kind = v.kind;
  if (
    typeof v.requestUUID !== 'string' ||
    !(HEX32.test(v.requestUUID) || UUID_FORM.test(v.requestUUID)) ||
    requestHex(v.requestUUID) !== requestHex(connectionUUID)
  ) throw new ExecPayloadError('Invalid exec requestUUID');
  const steps = commands(v.steps, 'steps', 1, 30, dialect);
  const safeChange = v.safeChange as SafeChange;
  if (
    !Number.isInteger(v.rollbackSeconds) || (v.rollbackSeconds as number) < 0 ||
    (v.rollbackSeconds as number) > 900
  ) throw new ExecPayloadError('Invalid exec rollbackSeconds');
  const rollbackSeconds = v.rollbackSeconds as number;
  let verify: string[] = [];
  let rollback: string[] = [];
  let backupName: string | null = null;
  let changeLog: ExecPayload['changeLog'] = null;
  if (kind === 'read') {
    if (safeChange !== 'none') throw new ExecPayloadError('Invalid exec safeChange');
    if (
      !Array.isArray(v.verify) || v.verify.length || !Array.isArray(v.rollback) ||
      v.rollback.length || v.backupName !== null || v.changeLog !== null
    ) throw new ExecPayloadError('Invalid exec read');
  } else {
    if (!SAFE_CHANGES.includes(safeChange as string)) {
      throw new ExecPayloadError('Invalid exec safeChange');
    }
    if (!SAFE_FOR_DIALECT[dialect]?.includes(safeChange)) {
      throw new ExecPayloadError('Invalid exec safeChange');
    }
    if (rollbackSeconds < 120 || steps.length * 30 + 60 > rollbackSeconds) {
      // Every step may take 30 s and the rollback must still be armed when the last one ends.
      throw new ExecPayloadError('Invalid exec rollbackSeconds');
    }
    verify = commands(v.verify, 'verify', 1, 10, dialect);
    if (safeChange === 'systemd_deadman') {
      rollback = commands(v.rollback, 'rollback', 1, 30, dialect);
    } else if (!Array.isArray(v.rollback) || v.rollback.length) {
      throw new ExecPayloadError('Invalid exec rollback');
    }
    if (typeof v.backupName !== 'string' || !BACKUP.test(v.backupName)) {
      throw new ExecPayloadError('Invalid exec backupName');
    }
    backupName = v.backupName;
    if (v.changeLog !== null) {
      const log = v.changeLog as Record<string, unknown> | undefined;
      if (
        !log || typeof log !== 'object' || Object.keys(log).some((k) =>
          k !== 'kind' && k !== 'line'
        ) ||
        !['script', 'file', 'report_only'].includes(log.kind as string) ||
        typeof log.line !== 'string' || !LOG_LINE.test(log.line)
      ) throw new ExecPayloadError('Invalid exec changeLog');
      const allowed = safeChange === 'routeros_safe_mode'
        ? ['script', 'report_only']
        : safeChange === 'systemd_deadman'
        ? ['file', 'report_only']
        : ['report_only'];
      if (!allowed.includes(log.kind as string)) {
        throw new ExecPayloadError('Invalid exec changeLog');
      }
      changeLog = { kind: log.kind as ChangeLogKind, line: log.line };
    }
  }
  if (typeof v.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(v.sha256)) {
    throw new ExecPayloadError('Invalid exec sha256');
  }
  const payload: ExecPayload = {
    kind,
    requestUUID: v.requestUUID,
    steps,
    verify,
    rollback,
    safeChange,
    rollbackSeconds,
    backupName,
    changeLog,
    sha256: v.sha256,
  };
  if (execSha256(payload) !== v.sha256) throw new ExecPayloadError('EXEC_PAYLOAD_MISMATCH');
  return payload;
}

const STATUSES = ['ok', 'blocked', 'failed', 'applied', 'rolled_back'];
const METHODS = ['safe_mode', 'scheduled_reboot', 'deadman_timer', 'none'];

/** Light shape and size check of a result produced by the worker (before it is posted). */
export function validExecResult(value: unknown): value is ExecResult {
  const r = value as ExecResult | null;
  if (!r || typeof r !== 'object' || !STATUSES.includes(r.status)) return false;
  if (!Array.isArray(r.steps) || r.steps.length > 200) return false;
  const rb = r.rollback;
  if (
    !rb || !METHODS.includes(rb.method) || typeof rb.armed !== 'boolean' ||
    typeof rb.fired !== 'boolean' || typeof rb.pendingReboot !== 'boolean'
  ) return false;
  if (
    r.error !== null &&
    (typeof r.error?.code !== 'string' || typeof r.error?.message !== 'string')
  ) return false;
  for (const step of r.steps) {
    if (
      !step || typeof step.command !== 'string' || typeof step.output !== 'string' ||
      typeof step.truncated !== 'boolean' ||
      !['system', 'step', 'verify', 'rollback'].includes(step.phase) ||
      !['allowed', 'blocked'].includes(step.verdict) ||
      (step.exitCode !== null && !Number.isInteger(step.exitCode))
    ) return false;
  }
  return new TextEncoder().encode(JSON.stringify(r)).length <= 1024 * 1024;
}
