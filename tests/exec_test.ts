// Exec mode (AI copilot, ST-F): payload contract, pre-classification, read and change flows
// against a fake device (exec channels, RouterOS-like safe mode, VRP-like prompts, Linux codes).

import { parseAssignment } from '../src/controller/contract.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { Gateway } from '../src/controller/gateway.ts';
import { buildDenylist } from '../src/controller/denylist.ts';
import { Session } from '../src/controller/session.ts';
import type { RuntimeEvent, SessionApi } from '../src/controller/session.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
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
  credential() {
    this.calls.push('credential');
    return Promise.resolve({
      credentialUseUUID: '11111111-2222-4333-8444-555555555555',
      wrapToken: 'wrap-token-0123456789',
      ttlSeconds: 30,
    });
  }
  credentialResult(_c: string, body: { result: string }) {
    this.calls.push(`credential:${body.result}`);
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

type Dialect = 'routeros' | 'linux' | 'vrp';

async function run(
  dialect: Dialect,
  exec: Options,
  device: ExecDeviceOptions & { level?: 'n1' | 'n2' | 'n3'; api?: FakeApi } = { kind: dialect },
) {
  const key = generateHostKey();
  const fake = await startExecDevice(key, { ...device, kind: dialect });
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
    unwrap: () => Promise.resolve({ username: 'support', password: PASSWORD }),
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
