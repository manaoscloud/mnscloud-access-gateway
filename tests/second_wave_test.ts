// Second-wave SSH dialects (ios, junos, fortios, bsd, vsol, dmos) and the Windows contract:
// unit negatives (contract, exact reads, change grammar, planning) and integration runs of the
// controller Session -> real worker process -> fake SSH device. The devices are protocol
// simulators: nothing here proves behaviour of real hardware or firmware.

import { parseAssignment } from '../src/controller/contract.ts';
import type { FinishBody } from '../src/controller/contract.ts';
import { Session } from '../src/controller/session.ts';
import type { RuntimeEvent, SessionApi } from '../src/controller/session.ts';
import { DirectLauncher } from '../src/controller/worker_launcher.ts';
import {
  canonicalExec,
  type ExecPayload,
  type ExecResult,
  execSha256,
  validExecResult,
} from '../src/shared/exec.ts';
import { planExec } from '../src/worker/exec.ts';
import { changeGrammarProblem, exactReadProblem, readProblem } from '../src/worker/exec_policy.ts';
import { loadRules } from '../src/worker/rules.ts';
import { validateInit } from '../src/worker/worker.ts';
import { assert, assertEquals, assertNotIncludes, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';
import { generateHostKey, PASSWORD, startExecDevice } from './hostile_ssh_server.ts';
import {
  CLI_PASSWORD,
  type CliDevice,
  type CliDeviceOptions,
  startCliDevice,
} from './vendor_cli_server.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const BACKUP = 'pre-ai-1a2b3c4d-20261119';

type Options = Partial<Omit<ExecPayload, 'sha256' | 'requestUUID'>>;

function payloadOf(connectionUUID: string, options: Options): ExecPayload {
  const base: ExecPayload = {
    kind: options.kind ?? 'read',
    requestUUID: connectionUUID.replaceAll('-', '').toUpperCase(),
    steps: options.steps ?? ['show version'],
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
  hostKey() {
    return Promise.resolve({ decision: 'accept' as const, pinned: true });
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
    this.results.push(result);
    return Promise.resolve();
  }
  finish(_c: string, body: FinishBody) {
    this.calls.push(`finish:${body.reason}`);
    this.finished = body;
    return Promise.resolve();
  }
}

type CliKind = CliDeviceOptions['kind'];

async function runSession(
  dialect: string,
  port: number,
  exec: Options,
  level: 'n1' | 'n2' | 'n3',
  password: string,
) {
  const api = new FakeApi();
  const connectionUUID = crypto.randomUUID();
  const assignment = parseAssignment({
    ...ASSIGNMENT,
    connectionUUID,
    mode: 'exec',
    ticket: null,
    target: { address: '127.0.0.1', port },
    shellDialect: dialect,
    username: 'support',
    level,
    recording: { enabled: false, partBytes: 65536, partSeconds: 5 },
    exec: payloadOf(connectionUUID, exec),
  });
  const session = new Session(assignment, {
    api,
    unwrap: () => Promise.resolve({ username: 'support', password }),
    launcher: new DirectLauncher(ROOT),
    networks: null,
    sandbox: { memoryMaxMB: 256, cpuQuotaPercent: 50, tasksMax: 64 },
    log: () => {},
    execResultRetryMs: [20, 20],
  });
  session.start();
  await session.done;
  return { api, result: api.results[0] };
}

/** One exec request through the controller Session and a real worker against a fake CLI device. */
async function run(
  kind: CliKind,
  exec: Options,
  device: Omit<CliDeviceOptions, 'kind'> = {},
  level: 'n1' | 'n2' | 'n3' = 'n2',
) {
  const fake = await startCliDevice(generateHostKey(), { kind, ...device });
  try {
    const { api, result } = await runSession(kind, fake.port, exec, level, CLI_PASSWORD);
    return { api, device: fake, result };
  } finally {
    await fake.close();
  }
}

const iosChange = (
  steps = ['interface GigabitEthernet0/1', 'description uplink-new'],
): Options => ({
  kind: 'change',
  steps,
  verify: ['show ip interface brief'],
  safeChange: 'reload_in',
  backupName: BACKUP,
});
const junosChange = (
  steps = ['set interfaces ge-0/0/1 description "uplink new"'],
): Options => ({
  kind: 'change',
  steps,
  verify: ['show version'],
  safeChange: 'commit_confirmed',
  backupName: BACKUP,
});

const typed = (d: CliDevice) => d.lines.map((l) => l.replace(/^\d+:/, ''));
const secretFree = (value: unknown) => {
  const text = JSON.stringify(value);
  assertNotIncludes(text, CLI_PASSWORD);
  assertNotIncludes(text, PASSWORD);
};

// ---------------------------------------------------------------------------------------------
// Unit: contract

const base = (id: string, patch: Record<string, unknown>) => ({
  ...ASSIGNMENT,
  connectionUUID: id,
  mode: 'exec',
  ticket: null,
  ...patch,
});

Deno.test('second wave contract: new dialects are read-only reads; windows never routes to SSH', () => {
  const id = ASSIGNMENT.connectionUUID;
  for (const dialect of ['ios', 'junos', 'fortios', 'bsd', 'vsol', 'dmos']) {
    const exec = payloadOf(id, { steps: ['show version'] });
    const a = parseAssignment(base(id, { shellDialect: dialect, exec }));
    assertEquals([a.shellDialect, a.protocol, a.exec?.kind], [dialect, 'ssh', 'read']);
    // A change needs a vendor rollback: only ios and junos have one (below).
    if (dialect !== 'ios' && dialect !== 'junos') {
      for (
        const safeChange of [
          'reload_in',
          'commit_confirmed',
          'systemd_deadman',
          'routeros_safe_mode',
        ]
      ) {
        assertThrows(
          () =>
            parseAssignment(
              base(id, {
                shellDialect: dialect,
                exec: payloadOf(id, {
                  kind: 'change',
                  steps: ['x'],
                  verify: ['y'],
                  safeChange: safeChange as ExecPayload['safeChange'],
                  backupName: BACKUP,
                  rollback: safeChange === 'systemd_deadman' ? ['z'] : [],
                }),
              }),
            ),
          /Invalid exec/,
        );
      }
    }
  }
  // Windows is WinRM only: SSH is refused, and WinRM serves no other dialect.
  const win = payloadOf(id, { steps: ['ver'] });
  assertThrows(
    () => parseAssignment(base(id, { shellDialect: 'windows', protocol: 'ssh', exec: win })),
    /protocol_refused/,
  );
  assertThrows(
    () =>
      parseAssignment(
        base(id, {
          shellDialect: 'linux',
          protocol: 'winrm',
          exec: payloadOf(id, { steps: ['x'] }),
        }),
      ),
    /protocol_refused/,
  );
  // Plain HTTP (5985) is never used; the default is 5986.
  assertThrows(
    () =>
      parseAssignment(
        base(id, {
          shellDialect: 'windows',
          protocol: 'winrm',
          target: { address: '203.0.113.10', port: 5985 },
          exec: win,
        }),
      ),
    /protocol_refused/,
  );
  const ok = parseAssignment(
    base(id, {
      shellDialect: 'windows',
      protocol: 'winrm',
      target: { address: '203.0.113.10' },
      exec: win,
    }),
  );
  assertEquals([ok.protocol, ok.target.port, ok.shellDialect], ['winrm', 5986, 'windows']);
  // Windows over WinRM is read only: no change, no rotation.
  for (const kind of ['change', 'rotate'] as const) {
    assertThrows(
      () =>
        parseAssignment(
          base(id, {
            shellDialect: 'windows',
            protocol: 'winrm',
            target: { address: '203.0.113.10', port: 5986 },
            exec: payloadOf(id, {
              kind,
              steps: kind === 'rotate' ? [] : ['ver'],
              verify: ['ver'],
              safeChange: 'reload_in',
              backupName: BACKUP,
            }),
          }),
        ),
      /Invalid exec/,
    );
  }
  // RouterOS API and SSH keep their literals.
  assertEquals(
    parseAssignment({ ...ASSIGNMENT, protocol: 'routeros_api' }).protocol,
    'routeros_api',
  );
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, protocol: 'telnet' }), /protocol_refused/);
});

Deno.test('second wave contract: safeChange per dialect, rotation refused, canonical hash unchanged', () => {
  const id = ASSIGNMENT.connectionUUID;
  const change = (dialect: string, patch: Options) =>
    parseAssignment(base(id, { shellDialect: dialect, exec: payloadOf(id, { ...patch }) }));
  // ios -> reload_in only, junos -> commit_confirmed only.
  assertEquals(change('ios', iosChange()).exec?.safeChange, 'reload_in');
  assertEquals(change('junos', junosChange()).exec?.safeChange, 'commit_confirmed');
  assertThrows(
    () => change('ios', { ...iosChange(), safeChange: 'commit_confirmed' }),
    /Invalid exec/,
  );
  assertThrows(
    () => change('junos', { ...junosChange(), safeChange: 'reload_in' }),
    /Invalid exec/,
  );
  assertThrows(
    () => change('ios', { ...iosChange(), safeChange: 'vrp5_schedule_reboot' }),
    /Invalid exec/,
  );
  assertThrows(() => change('ios', { ...iosChange(), safeChange: 'none' }), /Invalid exec/);
  // No rollback commands travel with a vendor timer, no free-form change log, a real budget.
  assertThrows(
    () => change('ios', { ...iosChange(), rollback: ['reload cancel'] }),
    /Invalid exec/,
  );
  assertThrows(
    () => change('junos', { ...junosChange(), changeLog: { kind: 'script', line: 'x' } }),
    /Invalid exec/,
  );
  assertThrows(() => change('ios', { ...iosChange(), rollbackSeconds: 60 }), /Invalid exec/);
  assertThrows(() => change('ios', { ...iosChange(), backupName: 'Bad Name' }), /Invalid exec/);
  // Rotation is refused for every new dialect.
  for (const dialect of ['ios', 'junos', 'fortios', 'bsd', 'vsol', 'dmos']) {
    assertThrows(
      () =>
        change(dialect, {
          kind: 'rotate',
          steps: [],
          verify: ['show version'],
          safeChange: dialect === 'junos' ? 'commit_confirmed' : 'reload_in',
          backupName: BACKUP,
        }),
      /Invalid exec/,
    );
  }
  // `inline help` is refused in any exec command of the prompt-driven CLIs.
  assertThrows(() => change('ios', { steps: ['show ?'] }), /Invalid exec/);
  // The canonical JSON keeps its shape and key order: no dialect, no new key.
  const p = payloadOf(id, iosChange());
  assertEquals(Object.keys(JSON.parse(canonicalExec(p))), [
    'kind',
    'steps',
    'verify',
    'rollback',
    'safeChange',
    'rollbackSeconds',
    'backupName',
    'changeLog',
  ]);
  assertEquals(p.sha256, execSha256(p));
  // A tampered step is a sha256 mismatch, not a silent fix.
  assertThrows(
    () =>
      parseAssignment(
        base(id, { shellDialect: 'ios', exec: { ...p, steps: ['interface Loopback9'] } }),
      ),
    /EXEC_PAYLOAD_MISMATCH/,
  );
  // New rollback methods are valid in a result.
  for (const method of ['scheduled_reload', 'confirmed_commit']) {
    assert(
      validExecResult({
        status: 'rolled_back',
        steps: [],
        rollback: {
          method,
          armed: true,
          fired: false,
          pendingReboot: method === 'scheduled_reload',
        },
        error: null,
      }),
      method,
    );
  }
  assert(
    !validExecResult({
      status: 'ok',
      steps: [],
      rollback: { method: 'nxos_rollback', armed: false, fired: false, pendingReboot: false },
      error: null,
    }),
  );
});

Deno.test('second wave worker init: dialect and protocol must pair, plain WinRM is refused', () => {
  const init = (patch: Record<string, unknown>) => ({
    t: 'init',
    connectionUUID: crypto.randomUUID(),
    mode: 'test',
    protocol: 'ssh',
    target: { address: '203.0.113.10', port: 22 },
    shellDialect: 'ios',
    username: 'support',
    level: 'n2',
    hostKey: { pinned: null },
    tls: { pinned: null },
    terminal: { cols: 80, rows: 24 },
    limits: {
      connectTimeoutSeconds: 5,
      idleSeconds: 60,
      maxOutputBytesPerSecond: 65536,
      maxOutputBytes: 1048576,
      verdictTimeoutSeconds: 30,
    },
    recording: false,
    ...patch,
  });
  assertEquals(validateInit(init({})).shellDialect, 'ios');
  const refused = (patch: Record<string, unknown>) => {
    try {
      validateInit(init(patch));
    } catch (error) {
      return (error as { reason: string }).reason;
    }
    return 'accepted';
  };
  assertEquals(refused({ shellDialect: 'windows' }), 'protocol_refused');
  assertEquals(refused({ protocol: 'winrm' }), 'protocol_refused');
  assertEquals(
    refused({
      protocol: 'winrm',
      shellDialect: 'windows',
      target: { address: '203.0.113.10', port: 5985 },
    }),
    'protocol_refused',
  );
  assertEquals(
    validateInit(
      init({
        protocol: 'winrm',
        shellDialect: 'windows',
        target: { address: '203.0.113.10', port: 5986 },
      }),
    ).protocol,
    'winrm',
  );
  assertEquals(refused({ shellDialect: 'nxos' }), 'invalid_assignment');
});

// ---------------------------------------------------------------------------------------------
// Unit: exact reads and change grammar

Deno.test('second wave reads: exact narrow commands only, no generic show/get allowlist', () => {
  const allowed: Record<string, string[]> = {
    ios: [
      'show version',
      'show ip interface brief',
      'show interfaces GigabitEthernet0/1',
      'show reload',
    ],
    junos: ['show version', 'show system uptime', 'show interfaces terse', 'show system commit'],
    fortios: [
      'get system status',
      'get system performance status',
      'get router info routing-table all',
    ],
    bsd: [
      'uname -a',
      'ifconfig -a',
      'ifconfig em0',
      'netstat -rn',
      'pfctl -s rules',
      'ping -c 3 192.0.2.1',
    ],
    vsol: ['show version', 'show clock'],
    dmos: ['show system', 'show alarm'],
    windows: ['ver', 'hostname', 'systeminfo', 'ipconfig /all', 'route print'],
  };
  for (const [dialect, commands] of Object.entries(allowed)) {
    for (const command of commands) {
      assertEquals(
        readProblem(dialect as never, command, null),
        null,
        `${dialect}: ${command}`,
      );
    }
  }
  const refused: [string, string][] = [
    // secret configuration dumps
    ['ios', 'show running-config'],
    ['ios', 'show startup-config'],
    ['junos', 'show configuration'],
    ['junos', 'show configuration | display set'],
    ['fortios', 'show full-configuration'],
    ['fortios', 'get system admin'],
    ['bsd', 'cat /conf/config.xml'],
    ['vsol', 'show running-config'],
    ['dmos', 'show running-config'],
    // abbreviations and inline help
    ['ios', 'sh ver'],
    ['ios', 'show ver'],
    ['ios', 'show ?'],
    ['ios', 'show version?'],
    ['junos', 'sh version'],
    ['junos', 'show ?'],
    ['fortios', 'get sys status'],
    // generic show/get is not allowlisted
    ['ios', 'show users'],
    ['ios', 'show snmp community'],
    ['junos', 'show system login'],
    ['fortios', 'get system global'],
    // composition, pipes and redirects
    ['ios', 'show version | include x'],
    ['ios', 'show version; reload'],
    ['ios', 'show version\nreload'],
    ['ios', 'show version > flash:x'],
    ['junos', 'show version | save /tmp/x'],
    ['junos', 'show version && request system reboot'],
    ['bsd', 'uname -a; reboot'],
    ['bsd', 'uname -a | sh'],
    ['bsd', 'uname -a > /tmp/x'],
    ['bsd', 'uname $(reboot)'],
    ['bsd', 'ls /conf'],
    ['bsd', 'ssh admin@192.0.2.1'],
    ['bsd', 'ping -c 3 192.0.2.1; reboot'],
    ['bsd', 'ping -c 99 192.0.2.1'],
    ['bsd', 'ifconfig em0 down'],
    ['bsd', 'sysctl -w net.inet.ip.forwarding=1'],
    ['bsd', 'systemctl status ssh'],
    // pivots and actions
    ['ios', 'ssh -l admin 192.0.2.1'],
    ['ios', 'reload in 1'],
    ['junos', 'start shell'],
    ['junos', 'request system reboot'],
    ['fortios', 'execute reboot'],
    // exactness
    ['ios', 'Show version'],
    ['ios', 'show  version'],
    ['ios', ' show version'],
    ['ios', 'show version '],
    ['windows', 'VER'],
    ['windows', 'ver & del x'],
    ['windows', 'ver > x'],
    ['windows', 'ipconfig /all | findstr x'],
    ['windows', 'ipconfig'],
    ['windows', 'powershell -c whoami'],
    ['windows', 'cmd /c ver'],
    ['windows', 'set'],
    ['windows', 'type c:\\windows\\system32\\config\\sam'],
    ['windows', 'ver\r\nshutdown /s'],
  ];
  for (const [dialect, command] of refused) {
    assert(readProblem(dialect as never, command, null) !== null, `${dialect}: ${command}`);
  }
  assertEquals(exactReadProblem('other', 'show version'), 'dialect not supported');
});

Deno.test('second wave change grammar: no save, commit, cancel, reboot, shell or auth change', () => {
  const ok = {
    ios: [
      'interface GigabitEthernet0/1',
      'description uplink to core',
      'shutdown',
      'no shutdown',
      'switchport mode access',
      'switchport access vlan 20',
      'switchport trunk allowed vlan add 30',
      'ip address 192.0.2.2 255.255.255.0',
      'vlan 40',
      'name guests',
    ],
    junos: [
      'set interfaces ge-0/0/1 description "uplink new"',
      'set interfaces ge-0/0/1 description uplink',
      'set interfaces ge-0/0/1 disable',
      'delete interfaces ge-0/0/1 disable',
      'set vlans guests vlan-id 40',
      'set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.2/24',
    ],
  };
  for (const [dialect, lines] of Object.entries(ok)) {
    for (const line of lines) {
      assertEquals(changeGrammarProblem(dialect as never, line), null, line);
    }
  }
  const bad = {
    ios: [
      'end',
      'exit',
      'do reload',
      'do write memory',
      'reload',
      'reload cancel',
      'reload in 1',
      'write memory',
      'copy running-config startup-config',
      'configure terminal',
      'enable secret x',
      'username admin secret x',
      'aaa new-model',
      'line vty 0 4',
      'snmp-server community x RW',
      'crypto key generate rsa',
      'no reload cancel',
      'archive',
      'event manager applet x',
      'tclsh',
      'interface GigabitEthernet0/1; reload',
      'description x\nreload',
      'description x | redirect flash:y',
      'description ' + 'x'.repeat(80),
      'switchport access vlan 5000',
      'ip address 192.0.2.2',
    ],
    junos: [
      'commit',
      'commit confirmed 1',
      'rollback 0',
      'rollback 1',
      'request system reboot',
      'run show version',
      'load override /tmp/x',
      'save /tmp/x',
      'exit',
      'exit configuration-mode',
      'top',
      'edit system',
      'set system root-authentication plain-text-password',
      'set system login user x class super-user',
      'delete system',
      'set system services ssh',
      'set interfaces ge-0/0/1 description "x" | display set',
      'set interfaces ge-0/0/1 description "x"; commit',
      'set interfaces ge-0/0/1 description "$(reboot)"',
      'set interfaces fxp0 unit 0 family inet address 192.0.2.2/24',
    ],
  };
  for (const [dialect, lines] of Object.entries(bad)) {
    for (const line of lines) {
      assert(changeGrammarProblem(dialect as never, line) !== null, `${dialect}: ${line}`);
    }
  }
  // Other dialects have no change grammar: planning refuses any automatic change for them.
  const id = ASSIGNMENT.connectionUUID;
  for (const dialect of ['fortios', 'bsd', 'vsol', 'dmos', 'windows'] as const) {
    const exec = {
      ...payloadOf(id, { kind: 'change', steps: ['x'], verify: ['y'] }),
      safeChange: 'reload_in' as const,
    };
    const planned = planExec(exec, loadRules(dialect), 'n3');
    assert(planned.blocked, dialect);
    assert(planned.items.some((i) => i.rule === 'change_unsupported'), dialect);
  }
});

Deno.test('second wave planning: a change line outside the grammar blocks the whole request', () => {
  const id = ASSIGNMENT.connectionUUID;
  const plan = (dialect: 'ios' | 'junos', steps: string[], level: 'n2' | 'n3' = 'n3') =>
    planExec(
      payloadOf(id, dialect === 'ios' ? iosChange(steps) : junosChange(steps)),
      loadRules(dialect),
      level,
    );
  assertEquals(plan('ios', ['interface GigabitEthernet0/1', 'description x']).blocked, false);
  assertEquals(plan('junos', ['set interfaces ge-0/0/1 description x']).blocked, false);
  for (const line of ['end', 'write memory', 'reload cancel', 'username x secret y', 'do reload']) {
    const planned = plan('ios', ['interface GigabitEthernet0/1', line]);
    assert(planned.blocked, line);
  }
  for (const line of ['commit', 'request system reboot', 'rollback 1', 'run start shell']) {
    assert(plan('junos', ['set interfaces ge-0/0/1 description x', line]).blocked, line);
  }
  // write_risky lines (ip address, shutdown) need N3; N2 is blocked by the level.
  assert(plan('ios', ['interface GigabitEthernet0/1', 'shutdown'], 'n2').blocked);
  assertEquals(plan('ios', ['interface GigabitEthernet0/1', 'shutdown'], 'n3').blocked, false);
});

// ---------------------------------------------------------------------------------------------
// Integration: reads

Deno.test('ios read: exact commands, pager dumped, secrets redacted, no config mode', async () => {
  const { result, device, api } = await run('ios', {
    steps: ['show version', 'show interfaces'],
  }, { pager: true, banner: '\npassword=Sup3rS3cret!' });
  assertEquals(result.status, 'ok');
  assertEquals(typed(device), ['terminal length 0', 'show version', 'show interfaces']);
  assertNotIncludes(JSON.stringify(result), 'Sup3rS3cret!');
  assertNotIncludes(result.steps[1].output, '--More--');
  assert(result.steps[1].output.includes('GigabitEthernet0/1 is up'));
  assert(result.steps[1].output.includes('GigabitEthernet0/2 is down'));
  assertEquals(result.rollback.method, 'none');
  assert(api.calls.includes('credential:used'));
  secretFree(result);
});

Deno.test('ios read: a secret dump or a shell pivot blocks the request before any connection', async () => {
  for (
    const steps of [['show version', 'show running-config'], ['sh ver'], [
      'show version | include x',
    ]]
  ) {
    const { result, device } = await run('ios', { steps });
    assertEquals(result.status, 'blocked');
    assertEquals(result.error?.code, 'EXEC_BLOCKED');
    assertEquals([device.connections, device.logins.length], [0, 0]);
  }
});

Deno.test('ios read: an unexpected confirmation is declined and fails closed', async () => {
  const { result, device } = await run('ios', { steps: ['show clock', 'show version'] }, {
    confirmOn: /^show clock$/,
  });
  assertEquals(result.status, 'failed');
  assertEquals(result.error?.code, 'UNEXPECTED_CONFIRMATION');
  assertEquals(device.answers, ['unexpected:no']);
  assert(!typed(device).includes('show version'));
});

Deno.test('ios read: a device error stops the request', async () => {
  const { result, device } = await run('ios', { steps: ['show inventory', 'show version'] }, {});
  // `show inventory` is answered; `show reload`-like errors come from commands the device lacks.
  assertEquals(result.status, 'ok');
  const failing = await run('ios', { steps: ['show ntp status', 'show version'] }, {});
  assertEquals(failing.result.status, 'failed');
  assertEquals(failing.result.error?.code, 'DEVICE_ERROR');
  assert(!typed(failing.device).includes('show version'));
  assertEquals(device.connections, 1);
});

Deno.test('ios read: a command that never returns to the prompt times out and closes', async () => {
  const { result, device } = await run('ios', { steps: ['show clock'] }, { hang: /^show clock$/ });
  assertEquals(result.status, 'failed');
  assertEquals(result.error?.code, 'COMMAND_TIMEOUT');
  assertEquals(result.steps[0].exitCode, 124);
  assertEquals(device.connections, 1);
});

Deno.test('ios read: the connection dropping mid-request fails with CONNECTION_LOST', async () => {
  const { result } = await run('ios', { steps: ['show clock', 'show version'] }, {
    dropOn: /^show clock$/,
  });
  assertEquals(result.status, 'failed');
  assertEquals(result.error?.code, 'CONNECTION_LOST');
});

Deno.test('junos, fortios, vsol and dmos reads: prompts, pager and errors', async () => {
  const junos = await run('junos', { steps: ['show version', 'show system uptime'] }, {
    banner: '\nsecret "TopSecretValue1"',
  });
  assertEquals(junos.result.status, 'ok');
  assertEquals(typed(junos.device), [
    'set cli screen-length 0',
    'show version',
    'show system uptime',
  ]);
  assertNotIncludes(JSON.stringify(junos.result), 'TopSecretValue1');
  const junosBad = await run('junos', { steps: ['show system storage', 'show version'] });
  assertEquals(junosBad.result.error?.code, 'DEVICE_ERROR');
  assert(!typed(junosBad.device).includes('show version'));

  const forti = await run('fortios', {
    steps: ['get system status', 'get system performance status'],
  }, {
    pager: true,
  });
  assertEquals(forti.result.status, 'ok');
  assert(forti.result.steps[1].output.includes('Memory: 40%'));
  assertNotIncludes(forti.result.steps[1].output, '--More--');
  const fortiBad = await run('fortios', { steps: ['get hardware status'] });
  assertEquals(fortiBad.result.error?.code, 'DEVICE_ERROR');

  for (const kind of ['vsol', 'dmos'] as const) {
    const r = await run(kind, { steps: [kind === 'vsol' ? 'show version' : 'show system'] });
    assertEquals(r.result.status, 'ok', kind);
    assertEquals(r.device.connections, 1);
  }
  const blocked = await run('fortios', { steps: ['show full-configuration'] });
  assertEquals(blocked.result.status, 'blocked');
  assertEquals(blocked.device.connections, 0);
});

Deno.test('bsd read: POSIX exec channels, non-zero exit fails, secret paths blocked', async () => {
  const key = generateHostKey();
  const fake = await startExecDevice(key, {
    kind: 'linux',
    respond: (command) => {
      if (command === 'uname -a') return { stdout: 'FreeBSD fw 14.0-RELEASE\n', code: 0 };
      if (command === 'uptime') return { stderr: 'boom\n', code: 1 };
      return undefined;
    },
  });
  try {
    const ok = await runSession(
      'bsd',
      fake.port,
      { steps: ['uname -a', 'hostname'] },
      'n2',
      PASSWORD,
    );
    assertEquals(ok.result.status, 'ok');
    assertEquals(fake.execs, ['uname -a', 'hostname']);
    const failed = await runSession(
      'bsd',
      fake.port,
      { steps: ['uptime', 'date'] },
      'n2',
      PASSWORD,
    );
    assertEquals(failed.result.error?.code, 'COMMAND_FAILED');
    assert(!fake.execs.includes('date'));
    const before = fake.execs.length;
    for (
      const steps of [['cat /conf/config.xml'], ['uname -a; reboot'], ['systemctl status ssh']]
    ) {
      const blocked = await runSession('bsd', fake.port, { steps }, 'n2', PASSWORD);
      assertEquals(blocked.result.status, 'blocked');
    }
    assertEquals(fake.execs.length, before);
  } finally {
    await fake.close();
  }
});

// ---------------------------------------------------------------------------------------------
// Integration: Cisco IOS `reload in`

Deno.test('ios change: lock retained through baseline, fresh verification, confirmation and persistence', async () => {
  const { result, device } = await run('ios', iosChange());
  assertEquals(result.status, 'applied');
  assertEquals(result.rollback, {
    method: 'scheduled_reload',
    armed: false,
    fired: false,
    pendingReboot: false,
  });
  const lines = typed(device);
  const commands = [
    'configure terminal lock',
    'do show configuration lock',
    'do show reload',
    'do show archive config differences nvram:startup-config system:running-config',
    `do dir flash:${BACKUP}-pre.cfg`,
    `do copy running-config flash:${BACKUP}-pre.cfg`,
    `do reload in 5 MNSCloud:${BACKUP}`,
    'interface GigabitEthernet0/1',
    'description uplink-new',
    `do copy running-config flash:${BACKUP}-post.cfg`,
    'do reload cancel',
    'do copy running-config startup-config',
  ];
  let last = -1;
  for (const command of commands) {
    const found = lines.indexOf(command, last + 1);
    assert(found > last, command + JSON.stringify(lines));
    last = found;
  }
  assert(!lines.includes('end') && !lines.includes('exit'));
  assert(device.lines.includes('1:show ip interface brief'));
  assert(
    device.lines.indexOf('1:show ip interface brief') < device.lines.indexOf('0:do reload cancel'),
  );
  assertEquals(device.events, ['lock-acquired', 'reload-armed', 'reload-cancelled', 'saved']);
  assertEquals(device.running, device.startup);
  assert(device.startup.includes('description uplink-new'));
  assertEquals(device.answers.filter((a) => a.startsWith('save:')), []);
  secretFree(result);
});

Deno.test('ios change: unsupported lock, malformed proof, dirty baseline and backup collisions refuse before mutation', async () => {
  const cases: [Omit<CliDeviceOptions, 'kind'>, string][] = [
    [{ lockUnsupported: true }, 'LOCK_UNPROVEN'],
    [{ lockOutput: 'LOCKED' }, 'LOCK_UNPROVEN'],
    [{ dirtyBaseline: true }, 'BASELINE_UNSAFE'],
    [{ unknownBaseline: true }, 'BASELINE_UNSAFE'],
    [{ noDiffCommand: true }, 'BASELINE_UNSAFE'],
    [{ userMode: true }, 'PRIVILEGE_REQUIRED'],
    [{ reloadPending: true }, 'RELOAD_PENDING'],
    [{ failBackup: true }, 'BACKUP_FAILED'],
    [{ backupCollision: true }, 'BACKUP_FAILED'],
  ];
  for (const [options, code] of cases) {
    const { result, device } = await run('ios', iosChange(), options);
    assertEquals(result.status, 'failed', code);
    assertEquals(result.error?.code, code);
    assert(!typed(device).includes('interface GigabitEthernet0/1'));
    assert(!typed(device).some((l) => l.startsWith('do reload in')));
    assert(!typed(device).includes('do reload cancel'));
    assertEquals(device.reloadScheduled, options.reloadPending ?? false);
    assert(!device.events.includes('saved'));
  }
});

Deno.test('ios change: rejected arm or foreign timer is never blindly cancelled', async () => {
  for (const options of [{ refuseReload: true }, { foreignTimerAfterArm: true }]) {
    const { result, device } = await run('ios', iosChange(), options);
    assertEquals(result.status, 'failed');
    assertEquals(result.error?.code, 'SCHEDULE_FAILED');
    assert(!typed(device).includes('do reload cancel'));
    assert(!typed(device).includes('interface GigabitEthernet0/1'));
    assertEquals(result.rollback.armed, false);
  }
});

Deno.test('ios change: step failure or ownership loss reports pending, never completed rollback', async () => {
  for (
    const [options, code] of [[{ badStep: 'description' }, 'STEP_FAILED'], [{
      loseLockAfterStep: true,
    }, 'LOCK_LOST']] as const
  ) {
    const { result, device } = await run('ios', iosChange(), options);
    assertEquals(result.status, 'failed');
    assertEquals(result.error?.code, code);
    assertEquals(result.rollback, {
      method: 'scheduled_reload',
      armed: true,
      fired: false,
      pendingReboot: true,
    });
    assert(!device.events.includes('saved'));
    assert(!device.events.includes('reload-cancelled'));
    device.fire();
    assertEquals(device.running, device.startup);
  }
});

Deno.test('ios change: verification failure retains timer; lock prevents foreign configuration writes', async () => {
  const bad = await run('ios', iosChange(), { failVerify: /^show ip interface brief$/ });
  assertEquals(bad.result.status, 'failed');
  assertEquals(bad.result.error?.code, 'VERIFY_FAILED');
  assert(bad.result.rollback.armed && bad.result.rollback.pendingReboot);
  assert(!bad.device.events.includes('saved'));
  const foreign = await run('ios', iosChange(), { foreignAfterApply: true });
  assertEquals(foreign.result.status, 'applied');
  assert(foreign.device.events.includes('foreign-write-refused'));
  assert(!foreign.device.running.includes('ntp server 203.0.113.9'));
});

Deno.test('ios change: save errors or readback mismatch after confirmation are not applied or rolled back', async () => {
  for (
    const options of [{ failSave: true }, { saveReadbackMismatch: true }, { saveLostAck: true }]
  ) {
    const { result, device } = await run('ios', iosChange(), options);
    assertEquals(result.status, 'failed');
    assertEquals(result.error?.code, 'SAVE_FAILED');
    assertEquals(result.rollback.armed, false);
    assertEquals(result.rollback.pendingReboot, false);
    assert(device.events.includes('reload-cancelled'));
    assert(result.error?.message.includes('unarmed'));
  }
});

Deno.test('ios change: cancel refusal, unknown acknowledgement and lost reply never save startup', async () => {
  for (
    const options of [{ cancelFails: true }, { cancelUnknownAck: true }, { cancelLostAck: true }]
  ) {
    const { result, device } = await run('ios', iosChange(), options);
    assertEquals(result.status, 'failed');
    assertEquals(
      result.error?.code,
      options.cancelLostAck ? 'CONFIRMATION_UNKNOWN' : 'CANCEL_FAILED',
    );
    assert(!device.events.includes('saved'));
    assertEquals(result.rollback.fired, false);
    if (options.cancelFails) assert(result.rollback.armed && result.rollback.pendingReboot);
    if (options.cancelLostAck) assert(!result.rollback.armed && result.rollback.pendingReboot);
  }
});

Deno.test('ios change: connection loss after arm reports pending state without claiming restoration', async () => {
  const { result, device } = await run('ios', iosChange(), {
    dropOn: /^interface GigabitEthernet0\/1$/,
  });
  assertEquals(result.status, 'failed');
  assertEquals(result.error?.code, 'CONNECTION_LOST');
  assert(result.rollback.armed && result.rollback.pendingReboot && !result.rollback.fired);
  assert(!device.events.includes('saved'));
});

Deno.test('ios change: lines outside the grammar block everything; risky lines need N3', async () => {
  for (
    const steps of [
      ['interface GigabitEthernet0/1', 'end'],
      ['interface GigabitEthernet0/1', 'write memory'],
      ['interface GigabitEthernet0/1', 'reload cancel'],
      ['interface GigabitEthernet0/1', 'username admin secret x'],
      ['interface GigabitEthernet0/1', 'do reload'],
    ]
  ) {
    const { result, device } = await run('ios', iosChange(steps), {}, 'n3');
    assertEquals(result.status, 'blocked');
    assertEquals(device.connections, 0);
  }
  const risky = await run('ios', iosChange(['interface GigabitEthernet0/1', 'shutdown']), {}, 'n2');
  assertEquals(risky.result.status, 'blocked');
  assertEquals(risky.device.connections, 0);
});

// ---------------------------------------------------------------------------------------------
// Integration: Junos exclusive candidate + commit confirmed

Deno.test('junos change: exclusive candidate, commit confirmed, new-session verify, confirm in the same context', async () => {
  const { result, device } = await run('junos', junosChange());
  assertEquals(result.status, 'applied', JSON.stringify([result.error, typed(device)]));
  assertEquals(result.rollback, {
    method: 'confirmed_commit',
    armed: false,
    fired: false,
    pendingReboot: false,
  });
  const lines = typed(device);
  const order = [
    'show system commit',
    'configure exclusive',
    'show | compare',
    `save /var/tmp/${BACKUP}-pre.conf`,
    'set interfaces ge-0/0/1 description "uplink new"',
    'show | compare',
    `save /var/tmp/${BACKUP}-post.conf`,
    'commit check',
    'commit confirmed 5',
    'commit',
    'run show system commit',
    'exit configuration-mode',
  ].map((l, n, all) => lines.indexOf(l, n ? lines.indexOf(all[n - 1]) + 1 : 0));
  assert(order.every((i, n) => i >= 0 && (n === 0 || i > order[n - 1])), JSON.stringify(lines));
  assert(device.lines.includes('1:show version'), 'verified in a fresh SSH connection');
  // The confirming `commit` came from connection 0, the one that holds the exclusive candidate.
  assert(device.lines.includes('0:commit'));
  assert(!device.lines.includes('1:commit'));
  assertEquals(device.events, ['commit-confirmed', 'commit']);
  assertEquals(device.confirmTimer, false);
  assert(device.committed.includes('set interfaces ge-0/0/1 description "uplink new"'));
  secretFree(result);
});

Deno.test('junos change: lock, foreign candidate, pending confirmed commit, backup, check -> nothing committed', async () => {
  const cases: [Omit<CliDeviceOptions, 'kind'>, string][] = [
    [{ locked: true }, 'CONFIG_LOCKED'],
    [{ candidateDirty: true }, 'CANDIDATE_DIRTY'],
    [{ confirmedPending: true }, 'COMMIT_PENDING'],
    [{ failBackupJunos: true }, 'BACKUP_FAILED'],
    [{ failCommitCheck: true }, 'COMMIT_CHECK_FAILED'],
    [{ badStep: 'description' }, 'STEP_FAILED'],
  ];
  for (const [options, code] of cases) {
    const { result, device } = await run('junos', junosChange(), options);
    assertEquals(result.status, 'failed', code);
    assertEquals(result.error?.code, code);
    assertEquals(result.rollback.armed, false, code);
    assertEquals(device.events.filter((e) => e.startsWith('commit')), [], code);
    assert(!device.committed.includes('set interfaces ge-0/0/1 description "uplink new"'), code);
  }
});

Deno.test('junos change: an unknown commit confirmed outcome keeps the timer, and failed verification reverts', async () => {
  const unknown = await run('junos', junosChange(), { failCommitConfirmed: true });
  assertEquals(unknown.result.status, 'failed');
  assertEquals(unknown.result.error?.code, 'COMMIT_UNKNOWN');
  assertEquals(unknown.result.rollback.armed, true);

  const verify = await run('junos', junosChange(), { failVerify: /^show version$/ });
  assertEquals(verify.result.status, 'rolled_back');
  assertEquals(verify.result.error?.code, 'VERIFY_FAILED');
  // The previous commit was restored at once and the confirmed commit is no longer pending.
  assertEquals(verify.result.rollback, {
    method: 'confirmed_commit',
    armed: false,
    fired: true,
    pendingReboot: false,
  });
  assertEquals(verify.device.committed, ['set interfaces ge-0/0/1 description old']);
  assertEquals(verify.device.confirmTimer, false);

  // If even the immediate revert fails the confirmed-commit timer is the rollback.
  const stuck = await run('junos', junosChange(), {
    failVerify: /^show version$/,
    failRollback1: true,
  });
  assertEquals(stuck.result.status, 'rolled_back');
  assertEquals(stuck.result.rollback.armed, true);
  assertEquals(stuck.device.confirmTimer, true);
  stuck.device.fire();
  assertEquals(stuck.device.committed, ['set interfaces ge-0/0/1 description old']);

  const confirm = await run('junos', junosChange(), { failConfirm: true });
  assertEquals(confirm.result.status, 'failed');
  assertEquals(confirm.result.error?.code, 'CONFIRM_FAILED');
  assertEquals(confirm.result.rollback.armed, true);
  assertEquals(confirm.device.confirmTimer, true);
  for (const r of [unknown, verify, stuck, confirm]) assert(r.result.status !== 'applied');
});

Deno.test('junos change: grammar and rotation are refused before any connection', async () => {
  for (const line of ['commit', 'request system reboot', 'rollback 1', 'run start shell', 'top']) {
    const { result, device } = await run(
      'junos',
      junosChange(['set interfaces ge-0/0/1 description x', line]),
      {},
      'n3',
    );
    assertEquals(result.status, 'blocked', line);
    assertEquals(device.connections, 0);
  }
});

Deno.test('second wave AI exact reads stay narrower than interactive N1 display controls', () => {
  for (
    const [dialect, line] of [
      ['fortios', 'execute date 2026-01-01'],
      ['fortios', 'execute time 00:00:00'],
      ['bsd', 'ps e'],
      ['bsd', 'ps auxe'],
      ['ios', 'show derived-config'],
      ['junos', 'set cli screen-length 0'],
    ] as const
  ) {
    assert(exactReadProblem(dialect, line) !== null, `${dialect}: ${line}`);
    const plan = planExec(
      payloadOf(ASSIGNMENT.connectionUUID, { steps: [line] }),
      loadRules(dialect),
      'n1',
    );
    assert(plan.blocked, `${dialect}: ${line}`);
  }
});
