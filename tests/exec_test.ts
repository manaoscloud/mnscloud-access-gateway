// Exec mode (AI copilot, ST-F): payload contract, pre-classification, read and change flows
// against a fake device (exec channels, RouterOS-like safe mode, VRP-like prompts, Linux codes).

import { createHash } from 'node:crypto';
import { parseAssignment } from '../src/controller/contract.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { Gateway } from '../src/controller/gateway.ts';
import { buildDenylist } from '../src/controller/denylist.ts';
import { Session } from '../src/controller/session.ts';
import type { RuntimeEvent, SessionApi } from '../src/controller/session.ts';
import { DirectLauncher, type WorkerLauncher } from '../src/controller/worker_launcher.ts';
import { type ExecPayload, type ExecResult, execSha256 } from '../src/shared/exec.ts';
import { fitResult, planExec } from '../src/worker/exec.ts';
import { deadlineExceeded } from '../src/worker/exec_policy.ts';
import { loadRules } from '../src/worker/rules.ts';
import { Redactor } from '../src/worker/redaction.ts';
import { validExecResult } from '../src/shared/exec.ts';
import type { SessionDeps } from '../src/controller/session.ts';
import { assert, assertEquals, assertNotIncludes, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import {
  type ExecDevice,
  type ExecDeviceOptions,
  generateHostKey,
  PASSWORD,
  startExecDevice,
} from './hostile_ssh_server.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const BACKUP = 'pre-ai-1a2b3c4d-20261114';
const LOG_LINE = '2026-11-14 MNSCloud: ajuste de teste (sessao 1a2b3c4d, aprovado por Tecnico)';

type Options = Partial<Omit<ExecPayload, 'sha256' | 'requestUUID'>>;

/** A payload as the API builds it: canonical sha256 over the documented key order. */
function payloadOf(connectionUUID: string, options: Options): ExecPayload {
  const kind = options.kind ?? 'read';
  const base: ExecPayload = {
    kind,
    requestUUID: connectionUUID.replaceAll('-', '').toUpperCase(),
    steps: options.steps ?? ['uptime'],
    verify: options.verify ?? [],
    rollback: options.rollback ?? [],
    safeChange: options.safeChange ?? 'none',
    rollbackSeconds: options.rollbackSeconds ?? 300,
    backupName: options.backupName ?? null,
    changeLog: options.changeLog ?? null,
    ...(options.autonomous ? { autonomous: true } : {}),
    sha256: '',
  };
  return { ...base, sha256: execSha256(base) };
}

class FakeApi implements SessionApi {
  calls: string[] = [];
  results: ExecResult[] = [];
  finished: FinishBody | null = null;
  failResultAttempts = 0;
  constructor(private readonly pinAccept = true) {}
  hostKey() {
    return Promise.resolve({ decision: 'accept' as const, pinned: this.pinAccept });
  }
  credential(_c: string, role?: 'current' | 'new') {
    this.calls.push(role === 'new' ? 'credential:new' : 'credential');
    return Promise.resolve({
      credentialUseUUID: role === 'new'
        ? '66666666-2222-4333-8444-555555555555'
        : '11111111-2222-4333-8444-555555555555',
      wrapToken: role === 'new' ? 'wrap-new-token-0123456789' : 'wrap-token-0123456789',
      ttlSeconds: 30,
    });
  }
  credentialResult(_c: string, body: { credentialUseUUID: string; result: string }) {
    const role = body.credentialUseUUID.startsWith('66666666') ? 'new:' : '';
    this.calls.push(`credential:${role}${body.result}`);
    return Promise.resolve();
  }
  events(_c: string, _events: RuntimeEvent[]) {
    return Promise.resolve();
  }
  recordingPart() {
    return Promise.resolve();
  }
  attach() {
    return Promise.resolve({ role: 'operator' as const });
  }
  detach() {
    return Promise.resolve();
  }
  execResult(_c: string, result: ExecResult) {
    this.calls.push('exec-result');
    if (this.failResultAttempts-- > 0) return Promise.reject(new Error('network down'));
    this.results.push(result);
    return Promise.resolve();
  }
  finish(_c: string, body: FinishBody) {
    this.calls.push(`finish:${body.reason}`);
    this.finished = body;
    return Promise.resolve();
  }
}

type Dialect = 'routeros' | 'linux' | 'vrp' | 'proxmox';

async function run(
  dialect: Dialect,
  exec: Options,
  device: Partial<ExecDeviceOptions> & {
    level?: 'n1' | 'n2' | 'n3';
    api?: FakeApi;
    /** Credential per wrapping token (default: the device password for both roles). */
    unwrap?: (token: string) => { username?: string; password?: string };
  } = {},
) {
  const key = generateHostKey();
  const fake = await startExecDevice(key, {
    ...device,
    kind: dialect === 'proxmox' ? 'linux' : dialect,
  });
  const api = device.api ?? new FakeApi();
  const connectionUUID = crypto.randomUUID();
  const assignment = parseAssignment({
    ...ASSIGNMENT,
    connectionUUID,
    mode: 'exec',
    ticket: null,
    target: { address: '127.0.0.1', port: fake.port },
    shellDialect: dialect,
    username: 'support',
    level: device.level ?? 'n2',
    recording: { enabled: false, partBytes: 65536, partSeconds: 5 },
    exec: payloadOf(connectionUUID, exec),
  });
  const logs: string[] = [];
  const session = new Session(assignment, {
    api,
    unwrap: (token) =>
      Promise.resolve(
        device.unwrap?.(token) ?? { username: 'support', password: PASSWORD },
      ),
    launcher: new DirectLauncher(ROOT),
    networks: null,
    sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
    log: (m) => logs.push(m),
    execResultRetryMs: [20, 20],
  });
  session.start();
  await session.done;
  await fake.close();
  return { api, device: fake, result: api.results[0], logs, connectionUUID };
}

const rosChange = (steps: string[], verify = ['/ip address print']): Options => ({
  kind: 'change',
  steps,
  verify,
  safeChange: 'routeros_safe_mode',
  backupName: BACKUP,
  changeLog: { kind: 'script', line: LOG_LINE },
});

const phases = (result: ExecResult) => result.steps.map((s) => `${s.phase}:${s.command}`);

Deno.test('exec contract: payload is validated strictly and the sha256 is recomputed', () => {
  const id = ASSIGNMENT.connectionUUID;
  const base = {
    ...ASSIGNMENT,
    mode: 'exec',
    ticket: null,
    exec: payloadOf(id, { steps: ['uptime'] }),
  };
  const parsed = parseAssignment({ ...base, shellDialect: 'linux' });
  assertEquals([parsed.mode, parsed.detachable, parsed.ticket, parsed.recording.enabled], [
    'exec',
    false,
    null,
    false,
  ]);
  assertEquals(parsed.exec?.steps, ['uptime']);
  // The sha256 does not match the payload: refused with the documented code.
  assertThrows(
    () =>
      parseAssignment({
        ...base,
        shellDialect: 'linux',
        exec: { ...base.exec, steps: ['uptime', 'df -h'] },
      }),
    /EXEC_PAYLOAD_MISMATCH/,
  );
  // exec is required for mode exec and refused otherwise.
  assertThrows(() => parseAssignment({ ...base, exec: undefined }), /exec/);
  assertThrows(
    () => parseAssignment({ ...ASSIGNMENT, exec: base.exec }),
    /Invalid exec/,
  );
  const bad = (patch: Record<string, unknown>, dialect = 'linux') => {
    const exec = { ...base.exec, ...patch };
    return () => parseAssignment({ ...base, shellDialect: dialect, exec });
  };
  assertThrows(bad({ steps: [] }), /Invalid exec/);
  assertThrows(bad({ steps: ['a\nb'] }), /Invalid exec/);
  assertThrows(bad({ steps: ['x'.repeat(1001)] }), /Invalid exec/);
  assertThrows(bad({ steps: Array(31).fill('uptime') }), /Invalid exec/);
  assertThrows(bad({ extra: 1 }), /Invalid exec/);
  assertThrows(bad({ kind: 'read', safeChange: 'systemd_deadman' }), /Invalid exec/);
  assertThrows(bad({ requestUUID: 'f'.repeat(32) }), /Invalid exec/);
  // A change needs a vendor safety net that matches the device; `none` is never sent.
  const change = (patch: Options, dialect: string) => {
    const exec = payloadOf(id, patch);
    return () => parseAssignment({ ...base, shellDialect: dialect, exec });
  };
  const ok: Options = {
    kind: 'change',
    steps: ['/system identity set name=x'],
    verify: ['/ip address print'],
    safeChange: 'routeros_safe_mode',
    backupName: BACKUP,
  };
  parseAssignment({ ...base, shellDialect: 'routeros', exec: payloadOf(id, ok) });
  assertThrows(change({ ...ok, safeChange: 'none' }, 'routeros'), /Invalid exec/);
  assertThrows(change(ok, 'linux'), /Invalid exec/);
  assertThrows(change({ ...ok, verify: [] }, 'routeros'), /Invalid exec/);
  assertThrows(change({ ...ok, rollbackSeconds: 60 }, 'routeros'), /Invalid exec/);
  assertThrows(change({ ...ok, backupName: 'Bad Name' }, 'routeros'), /Invalid exec/);
  assertThrows(
    change({ ...ok, changeLog: { kind: 'script', line: "it's" } }, 'routeros'),
    /Invalid exec/,
  );
  assertThrows(
    change({ ...ok, changeLog: { kind: 'script', line: 'a;b' } }, 'routeros'),
    /Invalid exec/,
  );
  const deadman: Options = {
    kind: 'change',
    steps: ['mkdir /tmp/x'],
    verify: ['uptime'],
    safeChange: 'systemd_deadman',
    backupName: BACKUP,
  };
  assertThrows(change(deadman, 'linux'), /Invalid exec/); // rollback commands are required
  parseAssignment({
    ...base,
    shellDialect: 'proxmox',
    exec: payloadOf(id, { ...deadman, rollback: ['rmdir /tmp/x'] }),
  });
  // The second SSH connection of a change does not exist on the single-stream connector bridge.
  assertThrows(
    () =>
      parseAssignment({
        ...base,
        shellDialect: 'routeros',
        exec: payloadOf(id, ok),
        path: 'connector',
        transport: 'connector',
        connectorUuid: id,
        connectorKeyFingerprint: 'SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=',
      }),
    /exec_change_unsupported_transport/,
  );
});

Deno.test('exec gateway: a payload that does not match is refused with a result and a finish', async () => {
  const finished = new Map<string, FinishBody>();
  const results: ExecResult[] = [];
  const api = new FakeApi();
  api.finish = (c, body) => {
    finished.set(c, body);
    return Promise.resolve();
  };
  api.execResult = (_c, result) => {
    results.push(result);
    return Promise.resolve();
  };
  const gateway = new Gateway({
    gatewayKey: 'gw-test1',
    edgeSources: ['10.0.0.5/32'],
    denylist: buildDenylist({ environment: 'production', labTargets: [] }),
    capacity: 2,
    version: '0.1.0',
    deps: {
      api,
      unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
      launcher: new DirectLauncher(ROOT),
      networks: null,
      sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
      log: () => {},
    },
  });
  const id = crypto.randomUUID();
  const exec = payloadOf(id, { steps: ['uptime'] });
  const outcome = await gateway.accept({
    ...ASSIGNMENT,
    connectionUUID: id,
    mode: 'exec',
    ticket: null,
    shellDialect: 'linux',
    exec: { ...exec, steps: ['uptime; reboot'] },
  });
  assertEquals(outcome, 'refused');
  assertEquals(results[0].status, 'failed');
  assertEquals(results[0].error?.code, 'EXEC_PAYLOAD_MISMATCH');
  assertEquals(finished.get(id)?.reason, 'exec_payload_mismatch');
  gateway.sweep();
  await gateway.drain();
});

Deno.test({
  name: 'exec read: a write command blocks the whole request and nothing runs',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, api } = await run('linux', {
      steps: ['uptime', 'systemctl restart nginx', 'cat /etc/shadow'],
    });
    assertEquals(result.status, 'blocked');
    assertEquals(result.steps.map((s) => s.verdict), ['allowed', 'blocked', 'blocked']);
    assertEquals(result.steps.map((s) => s.class), ['read', 'write_low', 'secret_read']);
    assertEquals(device.execs, []);
    assertEquals(device.authenticated, 0);
    assert(!api.calls.includes('credential'), 'no credential is pulled for a blocked request');
    // The result is posted before the finish, which is the usual exec_done.
    assertEquals(api.calls, ['exec-result', 'finish:exec_done']);
    assertEquals(api.finished?.state, 'closed');
  },
});

Deno.test({
  name: 'exec read: unknown commands are blocked, known reads run and secrets are redacted',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const unknown = await run('linux', { steps: ['nginx -t'] });
    assertEquals(unknown.result.status, 'blocked');
    assertEquals(unknown.device.execs, []);

    const { result, device, api } = await run('linux', {
      steps: ['uptime', 'echo hello', 'df -h'],
    }, {
      kind: 'linux',
      level: 'n1',
      respond: (command) =>
        command === 'echo hello'
          ? {
            stdout: `\x1b[31mhello\x1b[0m\npassword=hunter2 and ${PASSWORD}\nrouter admin\n`,
            stderr: 'warn\n',
            code: 0,
          }
          : command === 'df -h'
          ? { stdout: 'x'.repeat(100 * 1024) + '\nend\n', code: 3 }
          : { stdout: 'up 1 day\n', code: 0 },
    });
    assertEquals(result.status, 'ok');
    assertEquals(device.execs, ['uptime', 'echo hello', 'df -h']);
    assertEquals(device.connections, 1, 'one SSH connection, sequential channels');
    const [up, echo, df] = result.steps;
    assertEquals([up.phase, up.class, up.verdict, up.exitCode], ['step', 'read', 'allowed', 0]);
    assertEquals(echo.output.includes('\x1b'), false, 'ANSI is stripped');
    assert(echo.output.includes('hello'));
    assertNotIncludes(echo.output, PASSWORD);
    assertNotIncludes(echo.output, 'hunter2');
    assert(echo.output.includes('router admin'));
    assertEquals(df.exitCode, 3);
    assertEquals(df.truncated, true);
    assert(df.output.length <= 64 * 1024);
    assertNotIncludes(JSON.stringify(api.results), PASSWORD);
    assertEquals(api.calls, ['credential', 'credential:used', 'exec-result', 'finish:exec_done']);
  },
});

Deno.test({
  name: 'exec read: RouterOS runs one exec channel per command (no exit status is accepted)',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('routeros', {
      steps: ['/ip address print', '/interface print'],
    }, { kind: 'routeros', level: 'n1' });
    assertEquals(result.status, 'ok');
    assertEquals(device.execs, ['/ip address print', '/interface print']);
    assertEquals(result.steps.map((s) => s.exitCode), [null, null]);
    assertEquals(device.usernames, ['support']);
  },
});

Deno.test({
  name: 'exec read: VRP uses the shell, disables paging and ignores its output',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('vrp', {
      steps: ['display version', 'display ip interface brief'],
    });
    assertEquals(result.status, 'ok');
    assertEquals(device.shellLines, [
      'screen-length 0 temporary',
      'display version',
      'display ip interface brief',
    ]);
    assertEquals(result.steps.length, 2);
    assertEquals(result.steps[0].output.trim(), 'Huawei VRP simulated output');
    assertEquals(device.execs, []);
  },
});

Deno.test({
  name: 'exec change RouterOS: safe mode, steps, verify in a NEW connection, release, log, export',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, api } = await run(
      'routeros',
      rosChange(['/system identity set name=lab']),
    );
    assertEquals(result.status, 'applied');
    assertEquals(result.error, null);
    assertEquals(result.rollback, {
      method: 'safe_mode',
      armed: false,
      fired: false,
      pendingReboot: false,
    });
    // Safe mode taken with Ctrl-X, released with a second Ctrl-X; no revert.
    assertEquals(device.events, ['safe-taken', 'released']);
    assertEquals(device.rawInput.join('').split('\x18').length - 1, 2);
    // First connection `<user>+ct` (PTY); verification used a second, plain connection.
    assertEquals(device.usernames, ['support+ct4096w', 'support']);
    assertEquals(device.execs, ['/ip address print']);
    assertEquals(device.connections, 2);
    assertEquals(device.files, [BACKUP, 'pos-ai-1a2b3c4d-20261114']);
    assertEquals(device.committed.length, 3); // step, ensure script, append (the export is a file)
    assert(device.committed[0] === '/system identity set name=lab');
    assert(
      device.committed[1].startsWith(
        ':if ([:len [/system script find name=mnscloud-changelog]]=0)',
      ),
    );
    assert(device.committed[2].includes(`\\n# ${LOG_LINE}`));
    assert(device.committed[1].includes('comment="MNSCloud: Registro de alteracoes'));
    assert(device.shellLines.at(-1) === '/quit');
    // The backup runs before safe mode is taken and the first session never leaves safe mode early.
    assertEquals(phases(result).slice(0, 3), [
      `system:/export file=${BACKUP}`,
      'system:safe-mode take (Ctrl-X)',
      'step:/system identity set name=lab',
    ]);
    assert(phases(result).includes('verify:/ip address print'));
    assertEquals(api.calls.at(-1), 'finish:exec_done');
  },
});

Deno.test({
  name: 'exec change RouterOS: a failing step drops the socket without releasing safe mode',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run(
      'routeros',
      rosChange(['/system identity set name=lab', '/system identity set name=BAD']),
    );
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'STEP_FAILED');
    assertEquals(result.rollback.method, 'safe_mode');
    assertEquals(result.rollback.fired, true);
    assertEquals(device.events, ['safe-taken', 'reverted']);
    assertEquals(device.rawInput.join('').split('\x18').length - 1, 1, 'Ctrl-X sent only once');
    assertEquals(device.committed, [], 'nothing survived the revert');
    assertEquals(device.execs, [], 'verification never ran');
    assertEquals(device.shellLines.includes('/quit'), false);
    assert(result.steps.some((s) => s.phase === 'step' && s.output.includes('failure:')));
  },
});

Deno.test({
  name: 'exec change RouterOS: a failing verification in the new session rolls back',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('routeros', rosChange(['/system identity set name=lab']), {
      kind: 'routeros',
      respond: () => ({ stdout: 'failure: cannot reach gateway\n', code: null }),
    });
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'VERIFY_FAILED');
    assertEquals(device.events, ['safe-taken', 'reverted']);
    assertEquals(device.committed, []);
    assertEquals(device.usernames, ['support+ct4096w', 'support']);
    assertEquals(device.files, [BACKUP], 'no post-change export');
  },
});

Deno.test({
  name: 'exec change: policy blocks before anything runs',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    // N1 may not change anything; a risky command needs N3; destructive never runs.
    const n1 = await run('routeros', rosChange(['/system identity set name=lab']), {
      kind: 'routeros',
      level: 'n1',
    });
    assertEquals(n1.result.status, 'blocked');
    assertEquals(n1.device.authenticated, 0);
    const risky = await run(
      'routeros',
      rosChange(['/ip address add address=192.0.2.1/24 interface=ether1']),
      { kind: 'routeros', level: 'n2' },
    );
    assertEquals(risky.result.steps[0].class, 'write_risky');
    assertEquals(risky.result.status, 'blocked');
    const destructive = await run(
      'routeros',
      rosChange(['/system reset-configuration'], ['/ip address print']),
      { kind: 'routeros', level: 'n3' },
    );
    assertEquals(destructive.result.status, 'blocked');
    assertEquals(destructive.device.authenticated, 0);
    // The verification must be a known read.
    const writeVerify = await run(
      'routeros',
      rosChange(['/system identity set name=lab'], ['/system identity set name=x']),
      { kind: 'routeros', level: 'n3' },
    );
    assertEquals(writeVerify.result.status, 'blocked');
    assertEquals(writeVerify.result.steps.map((s) => s.verdict), ['allowed', 'blocked']);
    // N3 may run a risky (confirm) command.
    const allowed = await run(
      'routeros',
      rosChange(['/ip address add address=192.0.2.1/24 interface=ether1']),
      { kind: 'routeros', level: 'n3' },
    );
    assertEquals(allowed.result.status, 'applied');
  },
});

const vrpChange = (steps: string[], verify = ['display version']): Options => ({
  kind: 'change',
  steps,
  verify,
  safeChange: 'vrp5_schedule_reboot',
  backupName: BACKUP,
  changeLog: { kind: 'report_only', line: LOG_LINE },
});

Deno.test({
  name: 'exec change VRP: scheduled reboot is cancelled and the configuration saved after verify',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run(
      'vrp',
      vrpChange(['interface GigabitEthernet0/0/1', 'description MNSCloud: lab']),
    );
    assertEquals(result.status, 'applied');
    assertEquals(device.answers.map((a) => [a.command, a.answer]), [
      [`save ${BACKUP}.cfg`, 'Y'],
      ['schedule reboot delay 00:05', 'Y'],
      ['undo schedule reboot', 'Y'],
      ['save', 'Y'],
    ]);
    assertEquals(device.scheduledReboot, false);
    assertEquals(device.saved, true);
    assertEquals(device.connections, 2, 'verification in a new session');
    assertEquals(device.shellLines.filter((l) => l === 'system-view' || l === 'return').length, 2);
    assertEquals(result.rollback.method, 'scheduled_reboot');
    assertEquals(result.rollback.pendingReboot, false);
    // report_only writes nothing on the device.
    assertEquals(device.shellLines.some((l) => l.includes(LOG_LINE)), false);
  },
});

Deno.test({
  name: 'exec change VRP: an unexpected [Y/N] is answered N and fails; the reboot reverts',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run(
      'vrp',
      vrpChange(['interface GigabitEthernet0/0/1', 'description ASKME']),
    );
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'STEP_FAILED');
    assertEquals(result.rollback, {
      method: 'scheduled_reboot',
      armed: true,
      fired: false,
      pendingReboot: true,
    });
    const asked = device.answers.find((a) => a.command === 'description ASKME');
    assertEquals(asked?.answer, 'N');
    // Never saved after the failure and the reboot stays scheduled.
    assertEquals(device.answers.filter((a) => a.command === 'save').length, 0);
    assertEquals(device.scheduledReboot, true);
    assertEquals(device.connections, 1, 'no verification after a failed step');
  },
});

Deno.test({
  name: 'exec change VRP: step error and failed verification both leave the reboot pending',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const stepError = await run('vrp', vrpChange(['description ERRSTEP']));
    assertEquals(stepError.result.status, 'rolled_back');
    assertEquals(stepError.device.scheduledReboot, true);
    const verify = await run('vrp', vrpChange(['description MNSCloud: lab'], ['display fail']));
    assertEquals(verify.result.status, 'rolled_back');
    assertEquals(verify.result.error?.code, 'VERIFY_FAILED');
    assertEquals(verify.result.rollback.pendingReboot, true);
    assertEquals(verify.device.scheduledReboot, true);
    assertEquals(verify.device.answers.filter((a) => a.command === 'save').length, 0);
  },
});

const linuxChange = (steps: string[], rollback = ['mv /tmp/lab /tmp/lab.bak']): Options => ({
  kind: 'change',
  steps,
  verify: ['uptime'],
  rollback,
  safeChange: 'systemd_deadman',
  backupName: BACKUP,
  changeLog: { kind: 'file', line: LOG_LINE },
});

Deno.test({
  name: 'exec change Linux: dead-man timer armed as root, stopped after a good verification',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, connectionUUID } = await run('linux', linuxChange(['mkdir /tmp/lab']));
    assertEquals(result.status, 'applied');
    const unit = `mns-rb-${connectionUUID.replaceAll('-', '')}`;
    const script = btoa('mv /tmp/lab /tmp/lab.bak');
    assertEquals(device.execs, [
      'id -u',
      `systemd-run --unit=${unit} --on-active=300 --timer-property=AccuracySec=1s --property=Type=oneshot --property=TimeoutStartSec=120 /bin/sh -c 'echo ${script} | base64 -d | /bin/sh'`,
      'mkdir /tmp/lab',
      'uptime', // verification, second connection
      `systemctl stop ${unit}.timer`,
      `printf '%s\\n' '${LOG_LINE}' >> /etc/mnscloud-changelog`,
    ]);
    assertEquals(device.connections, 2, 'first connection and the verification');
    assertEquals(result.rollback, {
      method: 'deadman_timer',
      armed: false,
      fired: false,
      pendingReboot: false,
    });
  },
});

Deno.test({
  name: 'exec change Linux: a failing step runs the rollback now and stops the timer',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, connectionUUID } = await run(
      'linux',
      linuxChange(['mkdir /tmp/lab', 'touch /tmp/FAILME']),
    );
    const unit = `mns-rb-${connectionUUID.replaceAll('-', '')}`;
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'STEP_FAILED');
    assertEquals(result.rollback.fired, true);
    assertEquals(device.execs.slice(-2), [
      `systemctl start ${unit}.service`,
      `systemctl stop ${unit}.timer`,
    ]);
    assertEquals(device.execs.includes('uptime'), false, 'no verification after a failed step');
    assertEquals(result.steps.at(-3)?.exitCode, 1);
  },
});

Deno.test({
  name: 'exec change Linux: a failed verification rolls back; a failed arming changes nothing',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const verify = await run('linux', linuxChange(['mkdir /tmp/lab']), {
      kind: 'linux',
      respond: (command) => command === 'uptime' ? { stderr: 'down\n', code: 2 } : undefined,
    });
    assertEquals(verify.result.status, 'rolled_back');
    assertEquals(verify.result.error?.code, 'VERIFY_FAILED');
    assert(verify.device.execs.some((c) => c.startsWith('systemctl start mns-rb-')));

    const arm = await run('linux', linuxChange(['mkdir /tmp/lab']), {
      kind: 'linux',
      respond: (command) =>
        command.startsWith('systemd-run')
          ? { stderr: 'sudo: a password is required\n', code: 1 }
          : undefined,
    });
    assertEquals(arm.result.status, 'failed');
    assertEquals(arm.result.error?.code, 'ARM_FAILED');
    assertEquals(arm.device.execs.includes('mkdir /tmp/lab'), false, 'no step ran');
  },
});

Deno.test({
  name: 'exec change Linux: a non-root user gets sudo -n on system and AI commands',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('linux', linuxChange(['echo ok > /tmp/lab']), {
      kind: 'linux',
      uid: 1000,
    });
    assertEquals(result.status, 'applied');
    const sudo = device.execs.filter((c) => c.startsWith('sudo -n /bin/sh -c '));
    // arm, step, verify, stop timer, change log
    assertEquals(sudo.length, 5);
    assert(sudo.some((c) => c.includes(`'echo ok > /tmp/lab'`)));
    assert(sudo[0].includes('systemd-run --unit=mns-rb-'));
    // Only `id -u` runs as the login user; the (read-only) verification goes through sudo too.
    assert(device.execs.includes('id -u'));
    assert(sudo.some((c) => c.includes(`'uptime'`)));
  },
});

Deno.test({
  name: 'exec result: delivery is retried and the finish follows; no result is lost on failure',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const api = new FakeApi();
    api.failResultAttempts = 2;
    const { result } = await run('linux', { steps: ['uptime'] }, { kind: 'linux', api });
    assertEquals(result.status, 'ok');
    assertEquals(api.calls.filter((c) => c === 'exec-result').length, 3);
    assertEquals(api.calls.at(-1), 'finish:exec_done');
    assertEquals(api.results.length, 1, 'posted once');
  },
});

Deno.test({
  name: 'exec: a wrong device password reports the auth failure in the result',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const key = generateHostKey();
    const device: ExecDevice = await startExecDevice(key, { kind: 'linux' });
    const api = new FakeApi();
    const id = crypto.randomUUID();
    const session = new Session(
      parseAssignment({
        ...ASSIGNMENT,
        connectionUUID: id,
        mode: 'exec',
        ticket: null,
        shellDialect: 'linux',
        username: 'support',
        target: { address: '127.0.0.1', port: device.port },
        exec: payloadOf(id, { steps: ['uptime'] }),
      }),
      {
        api,
        unwrap: () => Promise.resolve({ username: 'support', password: 'wrong-password' }),
        launcher: new DirectLauncher(ROOT),
        networks: null,
        sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
        log: () => {},
        execResultRetryMs: [10],
      },
    );
    session.start();
    await session.done;
    await device.close();
    assertEquals(api.results[0].status, 'failed');
    assertEquals(api.results[0].error?.code, 'AUTH_FAILED');
    assertEquals(api.finished?.reason, 'auth_failed');
    assert(api.calls.includes('credential:auth_failed'));
  },
});

Deno.test('exec result: outputs shrink until the result fits the body cap', () => {
  const result: ExecResult = {
    status: 'ok',
    steps: Array.from({ length: 30 }, (_, i) => ({
      phase: 'step' as const,
      command: `cmd ${i}`,
      class: 'read',
      rule: null,
      verdict: 'allowed' as const,
      exitCode: 0,
      output: 'y'.repeat(64 * 1024),
      truncated: false,
      ms: 1,
    })),
    rollback: { method: 'none', armed: false, fired: false, pendingReboot: false },
    error: null,
  };
  const fitted = fitResult(result, 900 * 1024);
  assert(new TextEncoder().encode(JSON.stringify(fitted)).length <= 900 * 1024);
  assert(fitted.steps.every((s) => s.truncated));
});

// --- review fixes ---------------------------------------------------------------------------

type PlanDialect = 'routeros' | 'linux' | 'proxmox' | 'vrp';

/** Pre-classification only (no device): is every command of the request allowed? */
function planAllowed(
  dialect: PlanDialect,
  exec: Options,
  level: 'n1' | 'n2' | 'n3' = 'n3',
): boolean {
  const id = crypto.randomUUID();
  const payload = payloadOf(id, exec);
  return !planExec(payload, loadRules(dialect), level).blocked;
}

Deno.test('exec policy H1: reads that would write or act are refused', () => {
  const ros = [
    '/ip service dis ssh',
    '/user rem admin',
    '/system reb',
    '/ip address',
    ':put [:tostr [/system reboot]]',
    '/ip address print where [:len [/system reset-configuration]]',
    '/ping 192.0.2.1',
    '/interface monitor-traffic ether1',
    '/ip address print; /system reboot',
    '/ip address print follow',
    '/interface monitor ether1',
    '/tool torch interface=ether1',
  ];
  for (const command of ros) {
    assert(!planAllowed('routeros', { steps: [command] }), `routeros read allowed: ${command}`);
  }
  for (
    const command of [
      '/ip address print',
      '/system resource print',
      '/export',
      '/ping 192.0.2.1 count=3',
      '/interface monitor ether1 once',
    ]
  ) assert(planAllowed('routeros', { steps: [command] }), `routeros read refused: ${command}`);

  const linux = [
    'cat /etc/*',
    'ls /tmp/{a,b}',
    'ls ~root',
    'cd /tmp',
    'sort -o /tmp/x /tmp/y',
    'sort -uo /tmp/x /tmp/y',
    'uniq /tmp/a /tmp/b',
    'tree -o /tmp/x',
    'xxd -r /tmp/x',
    'sar -o /tmp/x',
    'dmesg -c',
    'dmesg --clear',
    'ss -K',
    'man -P cat ls',
    'yq -i . /tmp/x',
    'arping -U 192.0.2.1',
    'ping -f 192.0.2.1',
    'timedatectl set-time 2026-01-01',
    'loginctl terminate-user root',
    'hostnamectl set-hostname x',
    'cat /etc/shadow',
    'cat /root/.ssh/id_rsa',
    'cat /etc/ssl/server.key',
    'cat /etc/ssh/ssh_host_ed25519_key',
    'cat /etc/ssl/private',
  ];
  for (const dialect of ['linux', 'proxmox'] as const) {
    for (const command of linux) {
      assert(!planAllowed(dialect, { steps: [command] }), `${dialect} read allowed: ${command}`);
    }
  }
  for (const command of ['cat /etc/hostname', 'uptime', 'timedatectl status', 'sort /tmp/x']) {
    assert(planAllowed('linux', { steps: [command] }), `linux read refused: ${command}`);
  }
  assert(!planAllowed('vrp', { steps: ['sys'] }));
  assert(!planAllowed('vrp', { steps: ['quit'] }));
  assert(planAllowed('vrp', { steps: ['display version'] }));
});

Deno.test('exec contract H1c/H3/M2: other dialect, control chars, help and time budget', () => {
  const id = ASSIGNMENT.connectionUUID;
  const make = (dialect: string, exec: Options) =>
    parseAssignment({
      ...ASSIGNMENT,
      mode: 'exec',
      ticket: null,
      shellDialect: dialect,
      exec: payloadOf(id, exec),
    });
  assertThrows(() => make('other', { steps: ['ls'] }), /Invalid exec/);
  assertThrows(() => make('linux', { steps: ['ls\t/tmp'] }), /Invalid exec/);
  assertThrows(() => make('linux', { steps: ['ls\x7f'] }), /Invalid exec/);
  assertThrows(() => make('routeros', { steps: ['/ip address print ?'] }), /Invalid exec/);
  assertThrows(() => make('vrp', { steps: ['display ?'] }), /Invalid exec/);
  for (const bad of ['\u0085', '\u009b', '\u2028', '\u2029']) {
    assertThrows(() => make('linux', { steps: [`ls${bad}/tmp`] }), /Invalid exec/);
  }
  const logged = (line: string) => () =>
    make('routeros', {
      kind: 'change',
      steps: ['/system identity set name=x'],
      verify: ['/ip address print'],
      safeChange: 'routeros_safe_mode',
      backupName: BACKUP,
      changeLog: { kind: 'script', line },
    });
  logged('MNSCloud: ajuste (ok)')();
  for (const c of ['?', '[', ']', '{', '}', '|', '&', '<', '>']) {
    assertThrows(logged(`x ${c} y`), /Invalid exec/);
  }
  make('linux', { steps: ['ls /tmp/a?b'] }); // `?` is only inline help on RouterOS and VRP
  const change: Options = {
    kind: 'change',
    steps: Array(9).fill('/system identity set name=x'),
    verify: ['/ip address print'],
    safeChange: 'routeros_safe_mode',
    backupName: BACKUP,
    rollbackSeconds: 300,
  };
  // 9 steps * 30 s + 60 s > 300 s: the rollback could fire before the last step ends.
  assertThrows(() => make('routeros', change), /Invalid exec/);
  make('routeros', { ...change, steps: Array(8).fill('/system identity set name=x') });
  assert(!deadlineExceeded(1000, 1000 + 269000, 300));
  assert(deadlineExceeded(1000, 1000 + 270000, 300));
});

Deno.test('exec policy H4/H5: unknown commands and rollback disarming are refused', () => {
  const change = (dialect: PlanDialect, steps: string[], rollback: string[] = []): Options => ({
    kind: 'change',
    steps,
    rollback,
    verify: dialect === 'vrp' ? ['display version'] : ['uptime'],
    safeChange: dialect === 'vrp'
      ? 'vrp5_schedule_reboot'
      : dialect === 'routeros'
      ? 'routeros_safe_mode'
      : 'systemd_deadman',
    backupName: BACKUP,
  });
  const ros = [
    '/system reset-conf',
    '/sys scheduler add name=x',
    '/sys sched add name=x',
    '/system script ru x',
    '/tool netw add host=192.0.2.1',
    '/system scheduler add name=x',
  ];
  for (const command of ros) {
    assert(
      !planAllowed('routeros', { ...change('routeros', [command]), verify: ['/ip address print'] }),
      `routeros change allowed: ${command}`,
    );
  }
  for (
    const command of [
      ':execute "/system reboot"',
      '/system script run x',
      '/import file-name=x',
      '/tool netwatch add host=192.0.2.1',
      '/quit',
      '/system reboot',
      'system identity set name=x',
    ]
  ) {
    assert(
      !planAllowed('routeros', { ...change('routeros', [command]), verify: ['/ip address print'] }),
      `routeros change allowed: ${command}`,
    );
  }
  for (
    const command of [
      'sa',
      'sav',
      'save',
      'undo schedule reboot',
      'undo sch reboot',
      'schedule reboot delay 00:01',
      'startup saved-configuration x',
      'commit',
      'reboot',
      'quit',
      'r""eboot',
    ]
  ) assert(!planAllowed('vrp', change('vrp', [command])), `vrp change allowed: ${command}`);
  assert(planAllowed('vrp', change('vrp', ['description MNSCloud: lab'])));
  for (
    const command of [
      'systemctl stop mns-rb-abc.timer',
      'systemctl disable --now foo.timer',
      'systemd-run --on-active=1 true',
      'nohup sleep 1',
      'echo x | at now',
      'crontab -r',
      'sleep 300 &',
      'reboot',
      'shutdown now',
      'r""m -rf /tmp/x',
      '\\reboot',
    ]
  ) {
    assert(
      !planAllowed('linux', change('linux', [command], ['mv /tmp/a /tmp/b'])),
      `linux step: ${command}`,
    );
    assert(
      !planAllowed('linux', change('linux', ['mkdir /tmp/x'], [command])),
      `linux rb: ${command}`,
    );
  }
  assert(planAllowed('linux', change('linux', ['mkdir /tmp/x'], ['mv /tmp/a /tmp/b'])));
});

Deno.test('redaction H2: redactText masks whole PEM private keys, also unterminated ones', () => {
  const redactor = new Redactor(loadRules('linux').redact);
  const pem =
    '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1\nsecretsecret\n-----END OPENSSH PRIVATE KEY-----';
  const out = redactor.redactText(`before\n${pem}\nafter`);
  assertNotIncludes(out, 'secretsecret');
  assertNotIncludes(out, 'AAAAB3NzaC1');
  assert(out.includes('before') && out.includes('after'));
  const cut = redactor.redactText(`x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA`);
  assertNotIncludes(cut, 'MIIEowIBAAKCAQEA');
});

Deno.test('exec result L7: a malformed worker result is not accepted', () => {
  const good: ExecResult = {
    status: 'ok',
    steps: [],
    rollback: { method: 'none', armed: false, fired: false, pendingReboot: false },
    error: null,
  };
  assert(validExecResult(good));
  assert(!validExecResult({ ...good, status: 'weird' }));
  assert(!validExecResult({ ...good, steps: 'x' }));
  assert(!validExecResult({ ...good, rollback: null }));
  assert(!validExecResult({ ...good, error: { code: 1 } }));
});

Deno.test({
  name: 'exec gateway M4: a refused or full exec assignment still owes its result',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const finished = new Map<string, FinishBody>();
    const results = new Map<string, ExecResult>();
    let attempts = 0;
    const api = new FakeApi();
    api.finish = (c, body) => {
      finished.set(c, body);
      return Promise.resolve();
    };
    api.execResult = (c, result) => {
      if (attempts++ === 0) return Promise.reject(new Error('network down'));
      results.set(c, result);
      return Promise.resolve();
    };
    const deps: SessionDeps = {
      api,
      unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
      launcher: new DirectLauncher(ROOT),
      networks: null,
      sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
      log: () => {},
      execResultRetryMs: [5, 5],
    };
    const gateway = new Gateway({
      gatewayKey: 'gw-test1',
      edgeSources: ['10.0.0.5/32'],
      denylist: buildDenylist({ environment: 'production', labTargets: [] }),
      capacity: 2,
      version: '0.1.0',
      deps,
    });
    const raw = (id: string, address: string) => ({
      ...ASSIGNMENT,
      connectionUUID: id,
      mode: 'exec',
      ticket: null,
      shellDialect: 'linux',
      target: { address, port: 22 },
      exec: payloadOf(id, { steps: ['uptime'] }),
    });
    // Preflight refusal: loopback is on the denylist.
    const a = crypto.randomUUID();
    assertEquals(await gateway.accept(raw(a, '127.0.0.1')), 'refused');
    assertEquals(results.get(a)?.error?.code, 'EXEC_REFUSED');
    assertEquals(finished.get(a)?.state, 'refused');
    assert(attempts >= 2, 'the post was retried');
    // Gateway full (draining).
    const lab = new Gateway({
      gatewayKey: 'gw-test2',
      edgeSources: ['10.0.0.5/32'],
      denylist: buildDenylist({ environment: 'development', labTargets: ['203.0.113.10/32'] }),
      capacity: 2,
      version: '0.1.0',
      deps,
    });
    await lab.drain();
    const b = crypto.randomUUID();
    assertEquals(await lab.accept(raw(b, '203.0.113.10')), 'refused');
    assertEquals(results.get(b)?.error?.code, 'EXEC_REFUSED');
    assertEquals(finished.get(b)?.reason, 'gateway_full');
  },
});

Deno.test({
  name: 'exec change RouterOS M3: pager is dumped and a CR redraw still shows the prompt',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run(
      'routeros',
      rosChange(['/system identity set name=PAGER', '/system identity set name=REDRAW']),
    );
    assertEquals(result.status, 'applied');
    assert(device.events.includes('pager-dump'));
    const paged = result.steps.find((x) => x.command.endsWith('name=PAGER'));
    assert(paged?.output.includes('line3'));
    assertNotIncludes(paged?.output ?? '', 'Q quit');
    assertEquals(device.usernames[0], 'support+ct4096w');
  },
});

Deno.test({
  name:
    'exec change RouterOS M1/M5: connection lost after the commit stays applied; unconfirmed release is uncertain',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const lost = await run('routeros', rosChange(['/system identity set name=lab']), {
      kind: 'routeros',
      dropAfterRelease: true,
    });
    assertEquals(lost.result.status, 'applied');
    assert(['CHANGELOG_FAILED', 'EXPORT_FAILED'].includes(lost.result.error?.code ?? ''));
    assertEquals(lost.device.events.includes('reverted'), false);

    const silent = await run('routeros', rosChange(['/system identity set name=lab']), {
      kind: 'routeros',
      silentRelease: true,
    });
    assertEquals(silent.result.status, 'failed');
    assertEquals(silent.result.error?.code, 'RELEASE_UNCERTAIN');
  },
});

Deno.test({
  name: 'exec change Linux H6: a rollback that fails keeps the timer armed',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('linux', linuxChange(['touch /tmp/FAILME']), {
      kind: 'linux',
      respond: (command) =>
        command.startsWith('systemctl start mns-rb-') ? { stderr: 'failed\n', code: 1 } : undefined,
    });
    assertEquals(result.status, 'failed');
    assertEquals(result.error?.code, 'ROLLBACK_FAILED');
    assertEquals(result.rollback.armed, true);
    assertEquals(device.execs.some((c) => c.startsWith('systemctl stop')), false);
  },
});

// ---------------------------------------------------------------------------------------------
// ST-H: autonomous change flag and credential rotation (kind rotate)

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const NEW_PASSWORD = 'N3w-Rotated.Pass~2026';

const rotate = (dialect: Dialect, extra: Options = {}): Options => ({
  kind: 'rotate',
  steps: [],
  verify: [
    dialect === 'routeros'
      ? '/system identity print'
      : dialect === 'vrp'
      ? 'display version'
      : 'id -un',
  ],
  safeChange: dialect === 'routeros'
    ? 'routeros_safe_mode'
    : dialect === 'vrp'
    ? 'vrp5_schedule_reboot'
    : 'systemd_deadman',
  backupName: BACKUP,
  changeLog: dialect === 'vrp'
    ? { kind: 'report_only', line: LOG_LINE }
    : { kind: dialect === 'routeros' ? 'script' : 'file', line: LOG_LINE },
  ...extra,
});

/** Both credentials: `current` is the device password, `new` the replacement. */
const credentials = (next: { username?: string; password?: string } = {
  username: 'support',
  password: NEW_PASSWORD,
}) =>
(token: string) =>
  token.startsWith('wrap-new') ? next : { username: 'support', password: PASSWORD };

const noSecret = (value: unknown, logs: string[] = []) => {
  const text = JSON.stringify(value) + logs.join('\n');
  assertNotIncludes(text, PASSWORD);
  assertNotIncludes(text, NEW_PASSWORD);
};

Deno.test('exec contract ST-H: autonomous joins the canonical JSON only when true', () => {
  const id = ASSIGNMENT.connectionUUID;
  const change: Options = {
    kind: 'change',
    steps: ['/system identity set name=x'],
    verify: ['/ip address print'],
    safeChange: 'routeros_safe_mode',
    backupName: BACKUP,
  };
  const plain = payloadOf(id, change);
  const legacy = JSON.stringify({
    kind: 'change',
    steps: plain.steps,
    verify: plain.verify,
    rollback: [],
    safeChange: 'routeros_safe_mode',
    rollbackSeconds: 300,
    backupName: BACKUP,
    changeLog: null,
  });
  // ST-F payloads keep their hash.
  assertEquals(plain.sha256, sha(legacy));
  const auto = payloadOf(id, { ...change, autonomous: true });
  assert(auto.sha256 !== plain.sha256);
  assertEquals(auto.sha256, sha(legacy.slice(0, -1) + ',"autonomous":true}'));
  const base = { ...ASSIGNMENT, mode: 'exec', ticket: null, shellDialect: 'routeros' };
  assertEquals(parseAssignment({ ...base, exec: auto }).exec?.autonomous, true);
  // `false` is accepted and hashes like absent; it is not kept.
  const explicit = { ...plain, autonomous: false };
  assertEquals(parseAssignment({ ...base, exec: explicit }).exec?.autonomous, undefined);
  // The flag cannot be added to a signed payload, and only a change carries it.
  assertThrows(
    () => parseAssignment({ ...base, exec: { ...plain, autonomous: true } }),
    /EXEC_PAYLOAD_MISMATCH/,
  );
  assertThrows(() => parseAssignment({ ...base, exec: { ...plain, autonomous: 'yes' } }), /exec/);
  assertThrows(
    () =>
      parseAssignment({
        ...base,
        shellDialect: 'linux',
        exec: payloadOf(id, { steps: ['uptime'], autonomous: true }),
      }),
    /Invalid exec/,
  );
});

const FAKE_HASH = (password: string) =>
  '$6$fake$' + [...new TextEncoder().encode(password)].map((b) => b.toString(16).padStart(2, '0'))
    .join('');

const REDACTED_ROS = '/user set [find name="support"] password=<redacted>';

Deno.test('exec contract ST-H: rotate payload is strict and never travels over a connector', () => {
  const id = ASSIGNMENT.connectionUUID;
  const base = { ...ASSIGNMENT, mode: 'exec', ticket: null };
  const parse = (dialect: Dialect, options: Options) => () =>
    parseAssignment({ ...base, shellDialect: dialect, exec: payloadOf(id, options) });
  for (const dialect of ['routeros', 'vrp', 'linux'] as const) {
    assertEquals(parse(dialect, rotate(dialect))().exec?.kind, 'rotate');
  }
  assertEquals(parse('routeros', rotate('routeros'))().exec?.steps, []);
  assertThrows(parse('routeros', rotate('routeros', { steps: ['/user print'] })), /Invalid exec/);
  assertThrows(
    parse('routeros', rotate('routeros', { verify: Array(6).fill('/ip address print') })),
    /Invalid exec/,
  );
  assertThrows(parse('routeros', rotate('routeros', { verify: [] })), /Invalid exec/);
  assertThrows(parse('linux', rotate('linux', { rollback: ['true'] })), /Invalid exec/);
  assertThrows(parse('routeros', rotate('routeros', { rollbackSeconds: 60 })), /Invalid exec/);
  assertThrows(parse('routeros', rotate('routeros', { backupName: undefined })), /Invalid exec/);
  assertThrows(parse('routeros', rotate('routeros', { autonomous: true })), /Invalid exec/);
  assertThrows(parse('linux', rotate('routeros')), /Invalid exec/); // safe mode on a linux device
  assertThrows(
    () =>
      parseAssignment({
        ...base,
        shellDialect: 'routeros',
        exec: payloadOf(id, rotate('routeros')),
        path: 'connector',
        transport: 'connector',
        connectorUuid: id,
        connectorKeyFingerprint: 'SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=',
      }),
    /exec_change_unsupported_transport/,
  );
});

Deno.test('exec policy ST-H: rotate classifies only its verify reads', () => {
  const rules = loadRules('routeros');
  const id = ASSIGNMENT.connectionUUID;
  const plan = planExec(payloadOf(id, rotate('routeros')), rules, 'n3');
  assertEquals(plan.items.map((i) => i.phase), ['verify']);
  assertEquals(plan.blocked, false);
  const bad = planExec(
    payloadOf(id, rotate('routeros', { verify: ['/system reboot'] })),
    rules,
    'n3',
  );
  assertEquals(bad.blocked, true);
  // Below n3 a rotation is blocked by the level rule.
  const low = planExec(payloadOf(id, rotate('routeros')), rules, 'n2');
  assertEquals(low.items.find((i) => i.rule === 'rotate_level')?.verdict, 'blocked');
});

Deno.test({
  name: 'exec autonomous ST-H: only read and write_low steps run; anything else is blocked',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const risky = ['/ip firewall filter add chain=input action=drop comment=x'];
    const n3 = { kind: 'routeros', level: 'n3' } as const;
    const blocked = await run('routeros', { ...rosChange(risky), autonomous: true }, n3);
    assertEquals(blocked.result.status, 'blocked');
    assertEquals(blocked.result.error?.code, 'EXEC_BLOCKED');
    assertEquals(blocked.result.steps[0].class, 'write_risky');
    assertEquals(blocked.result.steps[0].rule, 'autonomous');
    assertEquals(blocked.result.steps[0].verdict, 'blocked');
    assertEquals(blocked.device.authenticated, 0);
    // The same step is not blocked by the autonomous rule when supervised.
    const supervised = await run('routeros', rosChange(risky), n3);
    assertEquals(supervised.result.status, 'applied');
    // A write_low step is fine in both modes, and an unknown line is blocked.
    const low = await run('routeros', {
      ...rosChange(['/system identity set name=lab']),
      autonomous: true,
    });
    assertEquals(low.result.status, 'applied');
    const unknown = await run('linux', { ...linuxChange(['nginx -t']), autonomous: true });
    assertEquals(unknown.result.status, 'blocked');
  },
});

Deno.test({
  name: 'exec rotate RouterOS: safe mode, verify with the NEW password, commit, no secret leaks',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, api, logs } = await run('routeros', rotate('routeros'), {
      kind: 'routeros',
      level: 'n3',
      unwrap: credentials(),
    });
    assertEquals(result.status, 'applied');
    assertEquals(result.error, null);
    assertEquals(device.password, NEW_PASSWORD);
    assertEquals(result.credentialActive, 'new');
    assertEquals(device.events.filter((e) => e !== 'pager-dump'), ['safe-taken', 'released']);
    // Login 1 is the current password (safe mode shell), login 2 the NEW password (verify).
    assertEquals(device.logins, [
      { username: 'support+ct4096w', ok: true },
      { username: 'support', ok: true },
    ]);
    assertEquals(
      result.steps.filter((s) => s.phase === 'step').map((s) => s.command),
      [REDACTED_ROS],
    );
    assertEquals(api.calls.filter((c) => c.startsWith('credential')), [
      'credential',
      'credential:used',
      'credential:new',
      'credential:new:used',
    ]);
    noSecret(result, logs);
  },
});

Deno.test({
  name: 'exec rotate RouterOS: a refused NEW login reverts the change; the old password works',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, api, logs } = await run('routeros', rotate('routeros'), {
      kind: 'routeros',
      level: 'n3',
      rejectNewPassword: true,
      unwrap: credentials(),
    });
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'VERIFY_FAILED');
    assertEquals(result.rollback.fired, true);
    assertEquals(device.password, PASSWORD);
    assert(device.events.includes('reverted'));
    assert(!device.events.includes('released'));
    assert(api.calls.includes('credential:new:auth_failed'));
    assert(device.logins.some((l) => !l.ok), 'the NEW login was refused');
    assertEquals(result.credentialActive, 'current');
    noSecret(result, logs);
  },
});

Deno.test({
  name: 'exec rotate: an unsafe password, another user or a reused password change nothing',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    for (
      const next of ['short', 'has space and a long enough value', PASSWORD, `${NEW_PASSWORD}"`]
    ) {
      const r = await run('routeros', rotate('routeros'), {
        kind: 'routeros',
        level: 'n3',
        unwrap: credentials({ username: 'support', password: next }),
      });
      assertEquals(r.result.status, 'failed');
      assertEquals(r.result.error?.code, 'CREDENTIAL_UNSAFE');
      assertEquals(r.device.password, PASSWORD);
      assertEquals(r.device.events, []);
      assertEquals(r.device.shellLines, []);
      assertEquals(r.device.connections, 1, 'nothing connects past the first login');
      noSecret(r.result, r.logs);
    }
    const other = await run('routeros', rotate('routeros'), {
      kind: 'routeros',
      level: 'n3',
      unwrap: credentials({ username: 'admin', password: NEW_PASSWORD }),
    });
    assertEquals(other.result.status, 'blocked');
    assertEquals(other.result.error?.code, 'CREDENTIAL_MISMATCH');
    assertEquals(other.device.password, PASSWORD);
    assertEquals(other.device.connections, 1);
    assertEquals(other.device.events, []);
    noSecret(other.result, other.logs);
  },
});

Deno.test({
  name:
    'exec rotate VRP: password set in aaa, verify with the NEW password, reboot cancelled, saved',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs } = await run('vrp', rotate('vrp'), {
      kind: 'vrp',
      level: 'n3',
      unwrap: credentials(),
    });
    assertEquals(result.status, 'applied');
    assertEquals(device.password, NEW_PASSWORD);
    assertEquals(device.savedPassword, NEW_PASSWORD);
    assertEquals(device.scheduledReboot, false);
    assertEquals(result.credentialActive, 'new');
    assertEquals(
      result.steps.filter((s) => s.phase === 'step').map((s) => s.command),
      ['aaa', 'local-user support password irreversible-cipher <redacted>', 'quit'],
    );
    assertEquals(device.logins.map((l) => l.ok), [true, true]);
    noSecret(result, logs);
  },
});

Deno.test({
  name: 'exec rotate VRP: a refused NEW login leaves the reboot pending; the reboot restores it',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs } = await run('vrp', rotate('vrp'), {
      kind: 'vrp',
      level: 'n3',
      rejectNewPassword: true,
      unwrap: credentials(),
    });
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'VERIFY_FAILED');
    assertEquals(result.rollback.pendingReboot, true);
    assertEquals(device.scheduledReboot, true);
    assertEquals(device.savedPassword, PASSWORD, 'the change was never saved');
    device.reboot();
    assertEquals(device.password, PASSWORD);
    noSecret(result, logs);
  },
});

Deno.test({
  name: 'exec rotate Linux: root-only rollback script via stdin, chpasswd via stdin, NEW verify',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs, connectionUUID } = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      unwrap: credentials(),
    });
    assertEquals(result.status, 'applied');
    assertEquals(device.password, NEW_PASSWORD);
    const unit = `mns-rb-${connectionUUID.replaceAll('-', '')}`;
    assertEquals(device.execs, [
      'id -u',
      'getent shadow support',
      `umask 077; install -m 600 /dev/stdin /run/${unit}.sh`,
      `systemd-run --unit=${unit} --on-active=300 --timer-property=AccuracySec=1s --property=Type=oneshot --property=TimeoutStartSec=120 /bin/sh /run/${unit}.sh`,
      'chpasswd',
      'id -un', // verification: second connection, NEW password
      `systemctl stop ${unit}.timer`,
      `rm -f /run/${unit}.sh`,
      `printf '%s\\n' '${LOG_LINE}' >> /etc/mnscloud-changelog`,
    ]);
    assertEquals(device.logins.map((l) => l.ok), [true, true]);
    assertEquals(device.timers.size, 0);
    assertEquals(device.scripts.size, 0, 'the rollback script is removed after the commit');
    // No secret (new password, old password or old hash) ever reaches an argv or the result.
    const argv = device.execs.join('\n');
    for (const value of [NEW_PASSWORD, PASSWORD, FAKE_HASH(PASSWORD)]) {
      assertNotIncludes(argv, value);
      assertNotIncludes(JSON.stringify(result), value);
      assertNotIncludes(logs.join('\n'), value);
    }
    assertEquals(
      result.steps.find((s) => s.command === 'getent shadow support')?.output,
      '',
    );
  },
});

Deno.test({
  name: 'exec rotate Linux: a refused NEW login restores the old hash from the script',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs } = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      rejectNewPassword: true,
      unwrap: credentials(),
    });
    assertEquals(result.status, 'rolled_back');
    assertEquals(result.error?.code, 'VERIFY_FAILED');
    assertEquals(device.password, PASSWORD);
    assertEquals(result.credentialActive, 'current');
    assertEquals(device.timers.size, 0);
    assertEquals(device.scripts.size, 0);
    assertEquals(result.rollback, {
      method: 'deadman_timer',
      armed: false,
      fired: true,
      pendingReboot: false,
    });
    noSecret(result, logs);
    assertNotIncludes(JSON.stringify(result), FAKE_HASH(PASSWORD));
  },
});

Deno.test({
  name: 'exec rotate Linux: when the timer cannot be stopped it stays armed and restores the hash',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device } = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      unwrap: credentials(),
      respond: (command) => command.startsWith('systemctl stop') ? { code: 1 } : undefined,
      timerFireMs: 1500,
    });
    assertEquals(result.status, 'failed');
    assertEquals(result.error?.code, 'DEADMAN_DISARM_FAILED');
    // The probe waited for the timer, which fired and restored the old hash.
    assertEquals(result.credentialActive, 'current');
    assertEquals(result.rollback.fired, true);
    assertEquals(device.timers.size, 0);
    assertEquals(device.password, PASSWORD);
  },
});

Deno.test({
  name:
    'exec rotate Linux: non-root uses sudo -n, a shadow failure or another user changes nothing',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const sudo = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      uid: 1000,
      unwrap: credentials(),
    });
    assertEquals(sudo.result.status, 'applied');
    assertEquals(sudo.device.password, NEW_PASSWORD);
    assert(sudo.device.execs.includes(`sudo -n /bin/sh -c 'chpasswd'`));
    assert(sudo.device.execs.includes(`sudo -n /bin/sh -c 'id -un'`));
    assertNotIncludes(sudo.device.execs.join('\n'), NEW_PASSWORD);

    const noShadow = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      unwrap: credentials(),
      respond: (command) => command.startsWith('getent') ? { code: 2 } : undefined,
    });
    assertEquals(noShadow.result.status, 'failed');
    assertEquals(noShadow.result.error?.code, 'SHADOW_UNAVAILABLE');
    assertEquals(noShadow.device.password, PASSWORD);
    assertEquals(noShadow.device.timers.size, 0);

    const locked = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      unwrap: credentials(),
      respond: (command) =>
        command.startsWith('getent') ? { stdout: 'support:!$6$x$y:1::::::\n', code: 0 } : undefined,
    });
    assertEquals(locked.result.error?.code, 'SHADOW_UNAVAILABLE');

    const other = await run('linux', rotate('linux'), {
      kind: 'linux',
      level: 'n3',
      unwrap: credentials({ username: 'root', password: NEW_PASSWORD }),
    });
    assertEquals(other.result.status, 'blocked');
    assertEquals(other.result.error?.code, 'CREDENTIAL_MISMATCH');
    assertEquals(other.device.execs, ['id -u'], 'nothing changed or armed');
    assertEquals(other.device.password, PASSWORD);
  },
});

// --- ST-H review: settle probe, VRP save order, level gate, script hygiene -------------------

const rotateOptions = (extra: Partial<ExecDeviceOptions> = {}) => ({
  level: 'n3' as const,
  unwrap: credentials(),
  ...extra,
});

Deno.test({
  name: 'exec rotate: needs support level n3 (rule rotate_level), nothing connects',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const r = await run('routeros', rotate('routeros'), {
      kind: 'routeros',
      unwrap: credentials(),
    });
    assertEquals(r.result.status, 'blocked');
    assertEquals(r.result.error?.code, 'EXEC_BLOCKED');
    assertEquals(r.result.steps.find((s) => s.rule === 'rotate_level')?.verdict, 'blocked');
    assertEquals(r.result.credentialActive, 'unknown');
    assertEquals(r.device.authenticated, 0);
    assertEquals(r.api.calls.includes('credential'), false);
  },
});

Deno.test({
  name: 'exec rotate RouterOS: an unconfirmed release is settled by a probe (new password wins)',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs } = await run(
      'routeros',
      rotate('routeros'),
      rotateOptions({ kind: 'routeros', silentRelease: true }),
    );
    assertEquals(result.error?.code, 'RELEASE_UNCERTAIN');
    assertEquals(result.status, 'applied', 'the probe proved the new password is live');
    assertEquals(result.credentialActive, 'new');
    assertEquals(device.password, NEW_PASSWORD);
    noSecret(result, logs);
  },
});

Deno.test({
  name:
    'exec rotate VRP: a failed save keeps the reboot armed (current); a failed undo after save is applied',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const save = await run('vrp', rotate('vrp'), rotateOptions({ kind: 'vrp', failSave: true }));
    assertEquals(save.result.status, 'rolled_back');
    assertEquals(save.result.error?.code, 'SAVE_FAILED');
    assertEquals(save.result.rollback.pendingReboot, true);
    assertEquals(save.result.credentialActive, 'current');
    assertEquals(save.device.scheduledReboot, true);
    save.device.reboot();
    assertEquals(save.device.password, PASSWORD);
    noSecret(save.result, save.logs);

    const undo = await run('vrp', rotate('vrp'), rotateOptions({ kind: 'vrp', failUndo: true }));
    assertEquals(undo.result.status, 'applied');
    assertEquals(undo.result.error?.code, 'CANCEL_FAILED');
    assertEquals(undo.result.rollback.pendingReboot, true);
    assertEquals(undo.result.credentialActive, 'new');
    undo.device.reboot();
    assertEquals(undo.device.password, NEW_PASSWORD, 'saved before the reboot');
    // The save comes before the reboot is cancelled.
    const order = undo.device.answers.map((a) => a.command);
    assert(order.indexOf('save') < order.indexOf('undo schedule reboot'));
    noSecret(undo.result, undo.logs);
  },
});

Deno.test({
  name: 'exec rotate VRP: a user that is not local is refused before anything is scheduled',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const r = await run('vrp', rotate('vrp'), rotateOptions({ kind: 'vrp', localUsers: [] }));
    assertEquals(r.result.status, 'failed');
    assertEquals(r.result.error?.code, 'CREDENTIAL_UNSUPPORTED');
    assertEquals(r.result.credentialActive, 'current');
    assertEquals(r.device.events, []);
    assertEquals(r.device.password, PASSWORD);
  },
});

Deno.test({
  name:
    'exec rotate Linux: connection lost after chpasswd or during the timer stop is settled by a probe',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const afterChange = await run(
      'linux',
      rotate('linux'),
      rotateOptions({ kind: 'linux', dropOn: /^chpasswd$/, timerFireMs: 1500 }),
    );
    assertEquals(afterChange.result.status, 'failed');
    assertEquals(afterChange.result.error?.code, 'CONNECTION_LOST');
    assertEquals(afterChange.result.credentialActive, 'current');
    assertEquals(afterChange.result.rollback.fired, true);
    assertEquals(afterChange.device.password, PASSWORD);
    noSecret(afterChange.result, afterChange.logs);

    const duringStop = await run(
      'linux',
      rotate('linux'),
      rotateOptions({
        kind: 'linux',
        dropOn: /^systemctl stop /,
        respond: (c) => c.startsWith('systemctl stop') ? { code: 1 } : undefined,
        timerFireMs: 1500,
      }),
    );
    assertEquals(duringStop.result.error?.code, 'CONNECTION_LOST');
    assertEquals(duringStop.result.credentialActive, 'current');
    assertEquals(duringStop.device.password, PASSWORD);
  },
});

Deno.test({
  name:
    'exec rotate Linux: arming or script failures leave no script; a failed rollback is settled',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const arm = await run(
      'linux',
      rotate('linux'),
      rotateOptions({
        kind: 'linux',
        respond: (c) => c.startsWith('systemd-run') ? { code: 1 } : undefined,
      }),
    );
    assertEquals(arm.result.error?.code, 'ARM_FAILED');
    assertEquals(arm.device.scripts.size, 0);
    assertEquals(arm.device.password, PASSWORD);
    assertEquals(arm.result.credentialActive, 'current');

    const install = await run(
      'linux',
      rotate('linux'),
      rotateOptions({
        kind: 'linux',
        respond: (c) => c.includes('install -m 600') ? { code: 1 } : undefined,
      }),
    );
    assertEquals(install.result.error?.code, 'ROLLBACK_SCRIPT_FAILED');
    assertEquals(install.device.scripts.size, 0);
    assertEquals(install.device.timers.size, 0);

    const rollback = await run(
      'linux',
      rotate('linux'),
      rotateOptions({
        kind: 'linux',
        rejectNewPassword: true,
        respond: (c) => c.startsWith('systemctl start') ? { code: 1 } : undefined,
        timerFireMs: 1500,
      }),
    );
    assertEquals(rollback.result.status, 'failed');
    assertEquals(rollback.result.error?.code, 'ROLLBACK_FAILED');
    assertEquals(rollback.result.credentialActive, 'current');
    assertEquals(rollback.device.password, PASSWORD);
    noSecret(rollback.result, rollback.logs);
  },
});

Deno.test({
  name: 'exec rotate proxmox: same flow as linux',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const { result, device, logs } = await run('proxmox', rotate('proxmox'), rotateOptions());
    assertEquals(result.status, 'applied');
    assertEquals(result.credentialActive, 'new');
    assertEquals(device.password, NEW_PASSWORD);
    noSecret(result, logs);
  },
});

Deno.test({
  name:
    'controller ST-H: role new is refused outside a rotate; a second request closes the open use',
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const sent: unknown[] = [];
    const scripted = (messages: unknown[]): WorkerLauncher => ({
      launch: () =>
        Promise.resolve({
          send: (m: unknown) => void sent.push(m),
          messages: (async function* () {
            for (const m of messages) {
              await new Promise((r) => setTimeout(r, 30));
              yield m;
            }
          })(),
          kill: () => Promise.resolve(),
          exited: Promise.resolve(0),
        }),
    });
    const exit = { t: 'exit', state: 'closed', reason: 'exec_done', bytesIn: 0, bytesOut: 0 };
    const start = async (kind: 'change' | 'rotate', messages: unknown[]) => {
      const api = new FakeApi();
      const connectionUUID = crypto.randomUUID();
      const options = kind === 'change'
        ? rosChange(['/system identity set name=x'])
        : rotate('routeros');
      const assignment = parseAssignment({
        ...ASSIGNMENT,
        connectionUUID,
        mode: 'exec',
        ticket: null,
        shellDialect: 'routeros',
        recording: { enabled: false, partBytes: 65536, partSeconds: 5 },
        exec: payloadOf(connectionUUID, options),
      });
      const session = new Session(assignment, {
        api,
        unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
        launcher: scripted(messages),
        networks: null,
        sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
        log: () => {},
        execResultRetryMs: [20, 20],
      });
      session.start();
      await session.done;
      return api;
    };
    const change = await start('change', [
      { t: 'started' },
      { t: 'need_credential', role: 'new' },
      exit,
    ]);
    assertEquals(change.calls.includes('credential:new'), false, 'no API call for role new');
    assert(
      sent.some((m) =>
        (m as { t: string; role?: string }).t === 'credential_unavailable' &&
        (m as { role?: string }).role === 'new'
      ),
    );
    sent.length = 0;
    const bad = await start('rotate', [
      { t: 'started' },
      { t: 'need_credential', role: 'root' },
      exit,
    ]);
    assertEquals(bad.calls.filter((c) => c.startsWith('credential')), []);
    // Two requests for the same role: the first use is closed as unused.
    const twice = await start('rotate', [
      { t: 'started' },
      { t: 'need_credential', role: 'new' },
      { t: 'need_credential', role: 'new' },
      exit,
    ]);
    assertEquals(
      twice.calls.filter((c) => c.startsWith('credential')),
      ['credential:new', 'credential:new:unused', 'credential:new', 'credential:new:unused'],
    );
  },
});
