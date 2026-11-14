// Exec mode of the worker (AI copilot, ST-F): runs a fixed, pre-classified list of commands on one
// device and returns the redacted outputs. Reads use one exec channel per command (RouterOS,
// Linux, Proxmox) or a shell with prompt detection (VRP, other). Changes run with the vendor's
// automatic rollback armed (RouterOS safe mode, VRP scheduled reboot, Linux systemd dead-man
// timer), are verified in a NEW SSH connection (same worker, same in-memory credential) and are
// committed only when the verification passes. No local program is ever run.

import { Buffer } from 'node:buffer';
import net from 'node:net';
// @ts-types="../types/ssh2.d.ts"
import ssh2 from 'ssh2';
import {
  type ExecPayload,
  type ExecPhase,
  type ExecResult,
  type ExecStatus,
  requestHex,
} from '../shared/exec.ts';
import type { CommandClass } from '../shared/framing.ts';
import type {
  CredentialRole,
  WorkerCredential,
  WorkerInit,
  WorkerToController,
} from '../shared/ipc.ts';
import { Classifier } from './classifier.ts';
import { deadlineExceeded, disarmsRollback, readProblem } from './exec_policy.ts';
import { decide } from './policy.ts';
import { type Redactor, stripAnsi } from './redaction.ts';
import type { DialectRules } from './rules.ts';
import { TerminalSanitizer } from './terminal.ts';

// deno-lint-ignore no-explicit-any
const { Client } = ssh2 as any;
/** Text shown in recorded commands in place of a secret. */
const REDACTED_MARK = '<redacted>';

export const COMMAND_TIMEOUT_MS = 20000;
export const OUTPUT_CAP_BYTES = 64 * 1024;
export const VERIFY_TIMEOUT_MS = 30000;
/** The JSON line of the result must fit the IPC limit and the API body cap (1 MiB). */
const RESULT_MAX_BYTES = 900 * 1024;
const PROMPT_TIMEOUT_MS = 15000;
/** Rotation settle probe: RouterOS safe mode revert, login timeout, dead-man wait and its cap. */
const ROS_SETTLE_MS = 3000;
const SETTLE_LOGIN_MS = 15000;
const SETTLE_POLL_MS = 2000;
const TIMER_MARGIN_MS = 15000;
const SETTLE_BUDGET_MS = 10 * 60 * 1000;
const STEP_TIMEOUT_MS = 30000;
const EXPORT_TIMEOUT_MS = 60000;

type Exit = Extract<WorkerToController, { t: 'exit' }>;

export interface ExecHelpers {
  init: WorkerInit;
  rules: DialectRules;
  redactor: Redactor;
  verifyKey(
    kind: 'ssh' | 'tls',
    algorithm: string,
    fingerprint: string,
    pinned: string | null,
  ): Promise<boolean>;
  requestCredential(role?: CredentialRole): Promise<WorkerCredential | null>;
  fingerprintOf(key: Uint8Array): string;
  algorithmOf(key: Uint8Array): string;
  onClose(handler: (reason: string) => void): void;
  send(message: WorkerToController): void;
  finish(state: Exit['state'], reason: string): Exit;
}

/** A failure that ends the request (carries the result error code and the finish reason). */
class ExecFail extends Error {
  constructor(
    readonly code: string,
    readonly state: Exit['state'] = 'failed',
    readonly reason = 'exec_done',
  ) {
    super(code);
  }
}

class ExecAbort extends Error {
  constructor(readonly reason: string) {
    super('aborted');
  }
}

/** Credential rotation (ST-H): what the gateway accepts as the new password and user. */
export const NEW_PASSWORD = /^[A-Za-z0-9._~+=-]{16,64}$/;
const DEVICE_USER = /^[A-Za-z0-9._@-]{1,64}$/;
const LINUX_USER = /^[a-z_][a-z0-9_-]{0,31}$/;
/** A crypt(3) hash as `getent shadow` prints it (locked or empty fields never match). */
const SHADOW_HASH = /^\$[0-9a-z]+\$[./A-Za-z0-9$=]+$/;

const ROS_ERROR =
  /^(failure|bad command|syntax error|expected |input does not match|no such item|ambiguous value|invalid value|value of [^ ]+ out of range|Script Error|ERROR)/im;
const VRP_ERROR = /^\s*Error:/m;
const ROS_PROMPT = /^\[[^\]\r\n]+\]\s*(?:\/[^<>\r\n]*)?(?:<SAFE>)?\s*>?\s*$/;
const VRP_PROMPT = /(?:^|\n)[<[][^\s<>[\]]{1,64}[>\]]\s*$/;
const PAGER = /-- \[Q quit\|D dump\|down\]/;
const YES_NO = /\[Y\/N\]\s*:?\s*$/i;

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const lastLineOf = (text: string) => text.slice(text.lastIndexOf('\n') + 1);

// ---------------------------------------------------------------------------------------------
// Pre-classification

export interface PlannedCommand {
  phase: ExecPhase;
  command: string;
  class: CommandClass;
  rule: string | null;
  unknown: boolean;
  verdict: 'allowed' | 'blocked';
}

/**
 * Classifies every command of the request before anything runs. Reads and verify commands must be
 * class `read` and known; AI changes follow the support level (allow|confirm) and never run
 * destructive or secret-reading commands.
 */
export function planExec(
  exec: ExecPayload,
  rules: DialectRules,
  level: WorkerInit['level'],
): { items: PlannedCommand[]; blocked: boolean } {
  const items: PlannedCommand[] = [];
  const stateful = rules.syntax === 'routeros';
  const classify = (
    list: string[],
    phase: ExecPhase,
    mode: 'read' | 'change',
    shared: boolean,
    autonomous = false,
  ) => {
    // Commands that run one per exec channel always start at the root menu; a shell keeps it.
    const kept = shared ? new Classifier(rules) : null;
    for (const command of list) {
      const classifier = kept ?? new Classifier(rules);
      const c = classifier.classify(command);
      classifier.commit(c);
      let allowed: boolean;
      if (mode === 'read') {
        allowed = c.class === 'read' && !c.unknown &&
          readProblem(rules.dialect, command, c.rule) === null;
      } else if (c.class === 'destructive' || c.class === 'secret_read' || c.unknown) {
        allowed = false;
      } else if (disarmsRollback(rules.dialect, command, c.rule)) {
        allowed = false;
      } else {
        const decision = decide(level, c.class);
        allowed = decision === 'allow' || decision === 'confirm';
      }
      let rule = c.rule;
      // Autonomous runbook step: only read and write_low, never an unknown line.
      if (allowed && autonomous && !(c.class === 'read' || c.class === 'write_low')) {
        allowed = false;
        rule = 'autonomous';
      }
      items.push({
        phase,
        command,
        class: c.class,
        rule,
        unknown: c.unknown,
        verdict: allowed ? 'allowed' : 'blocked',
      });
    }
  };
  if (exec.kind === 'read') {
    classify(exec.steps, 'step', 'read', false);
  } else if (exec.kind === 'rotate') {
    // The change itself comes from fixed per-dialect templates built in the worker; only the
    // verify reads are the API's. Replacing a login password needs the top support level.
    if (level !== 'n3') {
      items.push({
        phase: 'system',
        command: 'credential rotation',
        class: 'write_risky',
        rule: 'rotate_level',
        unknown: false,
        verdict: 'blocked',
      });
    }
    classify(exec.verify, 'verify', 'read', false);
  } else {
    classify(exec.steps, 'step', 'change', stateful, exec.autonomous === true);
    classify(exec.verify, 'verify', 'read', false);
    classify(exec.rollback, 'rollback', 'change', false);
  }
  return { items, blocked: items.some((i) => i.verdict === 'blocked') };
}

// ---------------------------------------------------------------------------------------------
// Output hygiene

/** Redacted, ANSI-free, capped text of a device output. */
function cleanOutput(redactor: Redactor, raw: string, truncated: boolean): string {
  let text = raw;
  // A cut output loses its last (possibly partial) line before redaction: no secret half.
  if (truncated) text = text.slice(0, text.lastIndexOf('\n') + 1);
  const safe = new TerminalSanitizer().push(text);
  const plain = stripAnsi(safe).text.replace(/\r\n/g, '\n').replace(/\r/g, '');
  return redactor.redactText(plain.replace(/-- \[Q quit\|D dump\|down\]\s*/g, ''));
}

/** Shrinks outputs until the serialized result fits the IPC line and the API body cap. */
export function fitResult(result: ExecResult, maxBytes = RESULT_MAX_BYTES): ExecResult {
  const size = () => new TextEncoder().encode(JSON.stringify(result)).length;
  while (size() > maxBytes) {
    const biggest = result.steps.reduce<ExecResult['steps'][number] | null>(
      (a, b) => (!a || b.output.length > a.output.length ? b : a),
      null,
    );
    if (!biggest || !biggest.output.length) break;
    biggest.output = biggest.output.slice(0, Math.floor(biggest.output.length / 2));
    biggest.truncated = true;
  }
  return result;
}

// ---------------------------------------------------------------------------------------------
// SSH plumbing

interface ChannelResult {
  raw: string;
  truncated: boolean;
  exitCode: number | null;
  lost: boolean;
}

function execChannel(
  // deno-lint-ignore no-explicit-any
  client: any,
  command: string,
  timeoutMs: number,
  stdin?: string,
): Promise<ChannelResult> {
  return new Promise((resolve) => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    let truncated = false;
    let settled = false;
    // deno-lint-ignore no-explicit-any
    let stream: any = null;
    const done = (exitCode: number | null, lost = false) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.removeListener('close', onClose);
      const bytes = new Uint8Array(size);
      let at = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, at);
        at += chunk.length;
      }
      resolve({ raw: new TextDecoder().decode(bytes), truncated, exitCode, lost });
    };
    const onClose = () => done(null, true);
    client.once('close', onClose);
    const timer = setTimeout(() => {
      try {
        stream?.close();
        stream?.destroy?.();
      } catch { /* closed */ }
      done(124);
    }, timeoutMs);
    const add = (chunk: Uint8Array) => {
      if (size + chunk.length > OUTPUT_CAP_BYTES) {
        truncated = true;
        chunk = chunk.subarray(0, Math.max(0, OUTPUT_CAP_BYTES - size));
      }
      if (chunk.length) {
        chunks.push(new Uint8Array(chunk));
        size += chunk.length;
      }
    };
    // deno-lint-ignore no-explicit-any
    client.exec(command, (error: Error | undefined, s: any) => {
      if (error || !s) {
        done(null, true);
        return;
      }
      stream = s;
      s.on('data', add);
      s.stderr?.on('data', add);
      s.on('close', (exitCode: unknown) => done(typeof exitCode === 'number' ? exitCode : null));
      // Secrets travel on stdin, never in the command line.
      if (stdin !== undefined) s.end(stdin);
    });
  });
}

/** A shell with prompt detection. Output is held as text; `take` hands it out and clears it. */
class Shell {
  #head = '';
  #tail = '';
  #truncated = false;
  #sanitizer = new TerminalSanitizer();
  #decoder = new TextDecoder();
  #waiter: (() => void) | null = null;
  #pagerAnswered = false;
  closed = false;

  // deno-lint-ignore no-explicit-any
  constructor(private readonly stream: any, readonly promptOf: (line: string) => boolean) {
    const onData = (chunk: Uint8Array) => this.#push(chunk);
    stream.on('data', onData);
    stream.stderr?.on('data', onData);
    stream.on('close', () => {
      this.closed = true;
      this.#waiter?.();
    });
  }

  #push(chunk: Uint8Array) {
    const text = this.#sanitizer.push(this.#decoder.decode(chunk, { stream: true }));
    if (this.#head.length < OUTPUT_CAP_BYTES * 2) this.#head += text;
    else this.#truncated = true;
    this.#tail = (this.#tail + text).slice(-4096);
    // RouterOS pager: ask for the rest of the output at once instead of paging.
    const paged = PAGER.test(lastLineOf(this.#view()));
    if (paged && !this.#pagerAnswered) this.stream.write('D');
    this.#pagerAnswered = paged;
    this.#waiter?.();
  }

  #view(): string {
    const source = this.#truncated ? this.#tail : this.#head;
    // A lone CR redraws the line: it starts a new one for prompt detection.
    return stripAnsi(source).text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  }

  get truncated() {
    return this.#truncated;
  }

  send(data: string) {
    this.stream.write(data);
  }

  /** Output received so far (text only) and clears it. */
  take(): { text: string; truncated: boolean } {
    const out = { text: this.#head, truncated: this.#truncated };
    this.#head = '';
    this.#tail = '';
    this.#truncated = false;
    return out;
  }

  /** Waits until `predicate(view)` holds; null on timeout or when the stream closed. */
  waitFor(predicate: (view: string) => boolean, timeoutMs: number): Promise<string | null> {
    return new Promise((resolve) => {
      const check = () => {
        const view = this.#view();
        if (predicate(view)) {
          cleanup();
          resolve(view);
        } else if (this.closed) {
          cleanup();
          resolve(null);
        }
      };
      const cleanup = () => {
        clearTimeout(timer);
        if (this.#waiter === check) this.#waiter = null;
      };
      const timer = setTimeout(() => {
        cleanup();
        resolve(null);
      }, timeoutMs);
      this.#waiter = check;
      check();
    });
  }

  atPrompt = (view: string) => this.promptOf(view);

  waitPrompt(timeoutMs: number) {
    return this.waitFor(this.atPrompt, timeoutMs);
  }
}

export interface ShellRun {
  output: string;
  truncated: boolean;
  timedOut: boolean;
  /** A `[Y/N]` question that was answered `N` (not a system step). */
  unexpectedConfirm: boolean;
  /** The shell closed while running. */
  closed: boolean;
}

/** Sends `command`, answers `[Y/N]` questions as told, and returns the output up to the prompt. */
async function runInShell(
  shell: Shell,
  command: string,
  timeoutMs: number,
  answer: 'Y' | 'N' | null,
): Promise<ShellRun> {
  shell.take();
  shell.send(command + '\r');
  let accumulated = '';
  let truncated = false;
  let unexpectedConfirm = false;
  const deadline = Date.now() + timeoutMs;
  const atEnd = (view: string) => shell.atPrompt(view) || YES_NO.test(lastLineOf(view));
  for (;;) {
    const view = await shell.waitFor(atEnd, Math.max(1, deadline - Date.now()));
    const part = shell.take();
    accumulated += part.text;
    truncated ||= part.truncated;
    if (view === null) {
      return {
        output: accumulated,
        truncated,
        timedOut: !shell.closed,
        unexpectedConfirm,
        closed: shell.closed,
      };
    }
    if (!shell.atPrompt(view) && YES_NO.test(lastLineOf(view))) {
      if (answer === 'Y') shell.send('Y\r');
      else {
        unexpectedConfirm = true;
        shell.send('N\r');
      }
      continue;
    }
    break;
  }
  return { output: accumulated, truncated, timedOut: false, unexpectedConfirm, closed: false };
}

/** Output of a shell run without the echoed command line and the final prompt line. */
function shellBody(run: ShellRun, command: string): string {
  const lines = run.output.replace(/\r\n/g, '\n').replace(/\r/g, '').split('\n');
  const prompt = lines.at(-1) ?? '';
  if (prompt.trim() && !run.timedOut) lines.pop();
  const probe = command.slice(0, 12);
  if (lines.length && lines[0].includes(probe)) lines.shift();
  return lines.join('\n');
}

// ---------------------------------------------------------------------------------------------

type Role = 'first' | 'verify' | 'probe';

export async function runExec(h: ExecHelpers): Promise<Exit> {
  const { init, redactor, rules } = h;
  const exec = init.exec!;
  const level = init.level;
  const dialect = init.shellDialect;
  const hex = requestHex(exec.requestUUID);
  const rotation = exec.kind === 'rotate';

  const result: ExecResult = {
    status: 'failed',
    steps: [],
    rollback: { method: 'none', armed: false, fired: false, pendingReboot: false },
    error: null,
  };
  const planned = planExec(exec, rules, level);
  const planOf = (phase: ExecPhase, command: string) =>
    planned.items.find((i) => i.phase === phase && i.command === command);

  const record = (
    phase: ExecPhase,
    command: string,
    exitCode: number | null,
    output: string,
    truncated: boolean,
    ms: number,
    plan?: PlannedCommand,
    /** A fixed text built by the gateway with the secret already left out. */
    literal = false,
  ) => {
    result.steps.push({
      phase,
      command: literal ? command : redactor.redactText(command),
      class: plan?.class ?? null,
      rule: plan?.rule ?? null,
      verdict: 'allowed',
      exitCode,
      output,
      truncated,
      ms,
    });
  };
  const sendResult = () => h.send({ t: 'exec_result', result: fitResult(result) });
  // A rotation holds its result until `settle` has checked which password works on the device.
  const emit = (status: ExecStatus, error: ExecResult['error'] = null) => {
    result.status = status;
    if (error) result.error = error;
    if (!rotation) sendResult();
  };

  if (planned.blocked) {
    for (const item of planned.items) {
      result.steps.push({
        phase: item.phase,
        command: redactor.redactText(item.command),
        class: item.class,
        rule: item.rule,
        verdict: item.verdict,
        exitCode: null,
        output: '',
        truncated: false,
        ms: 0,
      });
    }
    const count = planned.items.filter((i) => i.verdict === 'blocked').length;
    emit('blocked', {
      code: 'EXEC_BLOCKED',
      message: `${count} command(s) not allowed; nothing was executed.`,
    });
    if (rotation) {
      result.credentialActive = 'unknown';
      sendResult();
    }
    return h.finish('closed', 'exec_done');
  }

  // Abort: the controller asked to close (cancel, shutdown, duration limit).
  let abortNow: (error: ExecAbort) => void = () => {};
  const aborted = new Promise<never>((_, reject) => (abortNow = reject));
  aborted.catch(() => {});
  h.onClose((reason) => abortNow(new ExecAbort(reason)));
  const guard = <T>(p: Promise<T>): Promise<T> => Promise.race([p, aborted]);

  const secrets: {
    credential: WorkerCredential | null;
    /** Rotation only: the replacement password, the only credential the verify login may use. */
    next: WorkerCredential | null;
    fingerprint: string | null;
  } = {
    credential: null,
    next: null,
    fingerprint: null,
  };
  const clients: { end(): void; destroy(): void }[] = [];
  /** Rotation bookkeeping the settle probe decides from. */
  const rstate: {
    loggedIn: boolean;
    changeMayHaveRun: boolean;
    hint:
      | { kind: 'none' }
      | { kind: 'ros' }
      | { kind: 'timer'; armedAt: number }
      | { kind: 'vrp'; saved: boolean | null };
  } = { loggedIn: false, changeMayHaveRun: false, hint: { kind: 'none' } };
  // Verification commands are read-only; a non-root Linux login runs them like every other
  // command (set once the user is known).
  let verifyWire = (command: string) => command;

  const connect = (role: Role, suffix: string, only?: WorkerCredential) =>
    new Promise<{ end(): void; destroy(): void }>((resolve, reject) => {
      const client = new Client();
      const wrapper = {
        end: () => {
          try {
            client.end();
          } catch { /* closed */ }
        },
        destroy: () => {
          try {
            client.destroy();
          } catch { /* closed */ }
        },
        client,
      };
      clients.push(wrapper);
      let settled = false;
      let refusal: ExecFail | null = null;
      let attempts: Record<string, unknown>[] | null = null;
      const fail = (error: ExecFail) => {
        if (settled) return;
        settled = true;
        wrapper.destroy();
        reject(error);
      };
      client.on('ready', () => {
        if (settled) return;
        settled = true;
        resolve(wrapper);
      });
      client.on('error', (error: Error & { level?: string }) => {
        if (settled) return;
        if (refusal) fail(refusal);
        else if (
          /authentication methods failed/i.test(error.message) ||
          error.level === 'client-authentication'
        ) fail(new ExecFail('AUTH_FAILED', 'failed', 'auth_failed'));
        else fail(new ExecFail('CONNECT_FAILED', 'failed', 'connect_failed'));
      });
      client.on(
        'close',
        () => fail(refusal ?? new ExecFail('CONNECT_FAILED', 'failed', 'connect_failed')),
      );
      let sock: net.Socket | undefined;
      if (init.transport === 'connector') {
        sock = net.createConnection({ path: init.bridge! });
        sock.on('error', () => {});
        sock.write(init.bridgeSecret!);
      }
      client.connect({
        ...(sock ? { sock } : {}),
        host: init.target.address,
        port: init.target.port,
        username: init.username + suffix,
        ident: 'MNSCloud-AccessGateway',
        readyTimeout: init.limits.connectTimeoutSeconds * 1000,
        keepaliveInterval: 30000,
        keepaliveCountMax: 3,
        hostVerifier: (key: Uint8Array, verify: (ok: boolean) => void) => {
          const fingerprint = h.fingerprintOf(key);
          const decide_ = role === 'first'
            ? h.verifyKey('ssh', h.algorithmOf(key), fingerprint, init.hostKey.pinned)
            : Promise.resolve(fingerprint === secrets.fingerprint);
          decide_.then((ok) => {
            if (ok && role === 'first') secrets.fingerprint = fingerprint;
            if (!ok) {
              refusal = init.hostKey.pinned || role === 'verify'
                ? new ExecFail('HOSTKEY_MISMATCH', 'refused', 'hostkey_mismatch')
                : new ExecFail('HOSTKEY_REJECTED', 'refused', 'hostkey_rejected');
            }
            verify(ok);
            if (!ok) setTimeout(() => refusal && fail(refusal), 0);
          }).catch(() => {
            refusal = new ExecFail('HOSTKEY_REJECTED', 'refused', 'hostkey_rejected');
            verify(false);
            setTimeout(() => refusal && fail(refusal), 0);
          });
        },
        authHandler: (
          _methodsLeft: string[] | null,
          _partial: boolean | null,
          next: (method: Record<string, unknown> | false) => void,
        ) => {
          const advance = () => next(attempts?.shift() ?? false);
          if (attempts) return advance();
          // A rotation verifies with the NEW password only: the old credential must not log in.
          const passwordOnly = rotation && (role === 'verify' || role === 'probe');
          const build = (received: WorkerCredential) => {
            const username = (received.username || init.username) + suffix;
            const list: Record<string, unknown>[] = [];
            if (received.privateKey && !passwordOnly) {
              list.push({
                type: 'publickey',
                username,
                key: received.privateKey,
                passphrase: received.passphrase,
              });
            }
            if (received.password) {
              const password = received.password;
              list.push({ type: 'password', username, password });
              list.push({
                type: 'keyboard-interactive',
                username,
                prompt: (
                  _n: string,
                  _i: string,
                  _l: string,
                  prompts: unknown[],
                  finish: (r: string[]) => void,
                ) => finish(prompts.map(() => password)),
              });
            }
            attempts = list;
            advance();
          };
          if (role === 'probe') {
            if (only?.password) return build(only);
            return next(false);
          }
          if (passwordOnly) {
            if (secrets.next?.password) return build(secrets.next);
            return next(false);
          }
          if (secrets.credential) return build(secrets.credential);
          h.requestCredential().then((received) => {
            if (!received || (!received.password && !received.privateKey)) {
              next(false);
              setTimeout(
                () =>
                  fail(new ExecFail('CREDENTIAL_UNAVAILABLE', 'failed', 'credential_unavailable')),
                0,
              );
              return;
            }
            secrets.credential = received;
            build(received);
          }).catch(() => {
            next(false);
            setTimeout(
              () =>
                fail(new ExecFail('CREDENTIAL_UNAVAILABLE', 'failed', 'credential_unavailable')),
              0,
            );
          });
        },
      });
    });

  // deno-lint-ignore no-explicit-any
  const raw = (c: { end(): void }) => (c as any).client;

  const openShell = (
    // deno-lint-ignore no-explicit-any
    client: any,
    prompt: (line: string) => boolean,
    cols = 500,
  ): Promise<Shell> =>
    new Promise((resolve, reject) => {
      client.shell(
        { term: 'vt100', cols, rows: 50 },
        // deno-lint-ignore no-explicit-any
        (error: Error | undefined, stream: any) => {
          if (error || !stream) reject(new ExecFail('SHELL_REFUSED', 'failed', 'shell_refused'));
          else resolve(new Shell(stream, prompt));
        },
      );
    });

  /** One command over an exec channel, recorded. */
  const runChannel = async (
    client: unknown,
    phase: ExecPhase,
    command: string,
    wire = command,
    timeoutMs = COMMAND_TIMEOUT_MS,
    stdin?: string,
  ) => {
    const started = Date.now();
    const r = await guard(execChannel(client, wire, timeoutMs, stdin));
    const output = cleanOutput(redactor, r.raw, r.truncated);
    record(
      phase,
      command,
      r.exitCode,
      output,
      r.truncated,
      Date.now() - started,
      planOf(phase, command),
    );
    if (r.lost) throw new ExecFail('CONNECTION_LOST');
    return { ...r, output };
  };

  /** One command in a shell, recorded. */
  const runShell = async (
    shell: Shell,
    phase: ExecPhase,
    command: string,
    timeoutMs: number,
    answer: 'Y' | 'N' | null,
    display = command,
  ) => {
    const started = Date.now();
    const run = await guard(runInShell(shell, command, timeoutMs, answer));
    let output = cleanOutput(redactor, shellBody(run, command), run.truncated);
    let truncated = run.truncated;
    if (output.length > OUTPUT_CAP_BYTES) {
      output = output.slice(0, output.lastIndexOf('\n', OUTPUT_CAP_BYTES) + 1 || OUTPUT_CAP_BYTES);
      truncated = true;
    }
    record(
      phase,
      display,
      run.timedOut ? 124 : null,
      output,
      truncated,
      Date.now() - started,
      planOf(phase, display),
      display !== command,
    );
    if (run.closed) throw new ExecFail('CONNECTION_LOST');
    return { run, output };
  };

  const connectFirst = async (suffix: string) => {
    try {
      const conn = await guard(connect('first', suffix));
      rstate.loggedIn = true;
      h.send({ t: 'credential_result', role: 'current', result: 'used' });
      return conn;
    } catch (error) {
      if (error instanceof ExecFail && error.reason === 'auth_failed') {
        h.send({ t: 'credential_result', role: 'current', result: 'auth_failed' });
      }
      throw error;
    }
  };

  // --- verification in a NEW SSH session -----------------------------------------------------

  /** Runs the verify commands in a second connection; true when they all pass. */
  const verifyNewSession = async (): Promise<boolean> => {
    let ok = false;
    const before = clients.length;
    let connection: { end(): void; destroy(): void } | null = null;
    const work = (async () => {
      try {
        connection = await connect('verify', '');
      } catch (error) {
        // The replacement password did not log in: report it for the credential use.
        if (rotation && error instanceof ExecFail && error.reason === 'auth_failed') {
          h.send({ t: 'credential_result', role: 'new', result: 'auth_failed' });
        }
        throw error;
      }
      if (rotation) h.send({ t: 'credential_result', role: 'new', result: 'used' });
      const client = raw(connection);
      if (dialect === 'vrp') {
        const shell = await openShell(client, (view) => VRP_PROMPT.test('\n' + lastLineOf(view)));
        if (!(await shell.waitPrompt(PROMPT_TIMEOUT_MS))) return false;
        await runInShell(shell, 'screen-length 0 temporary', COMMAND_TIMEOUT_MS, null);
        for (const command of exec.verify) {
          const { run, output } = await runShell(shell, 'verify', command, COMMAND_TIMEOUT_MS, 'N');
          if (run.timedOut || run.unexpectedConfirm || VRP_ERROR.test(output)) return false;
        }
        return true;
      }
      for (const command of exec.verify) {
        const r = await runChannel(client, 'verify', command, verifyWire(command));
        // RouterOS gives no exit status over exec; Linux must exit 0.
        if (dialect === 'routeros' ? r.exitCode !== null && r.exitCode !== 0 : r.exitCode !== 0) {
          return false;
        }
        if (dialect === 'routeros' && ROS_ERROR.test(r.output)) return false;
      }
      return true;
    })();
    work.catch(() => {});
    const timeout = new Promise<boolean>((resolve) =>
      setTimeout(() => resolve(false), VERIFY_TIMEOUT_MS)
    );
    try {
      ok = await guard(Promise.race([work, timeout]));
    } catch (error) {
      if (error instanceof ExecAbort) throw error;
      ok = false;
    } finally {
      // Also a verify connection that never got to `ready` (timeout while connecting).
      for (const client of clients.slice(before)) client.destroy();
    }
    return ok;
  };

  // --- credential rotation (kind rotate) ------------------------------------------------------

  interface Rotation {
    user: string;
    password: string;
  }
  interface ChangeStep {
    command: string;
    /** What the result records when the command carries a secret. */
    display?: string;
  }

  /**
   * Fetches and checks the replacement credential before anything is changed. Returns null after
   * emitting `blocked` (CREDENTIAL_MISMATCH) or `failed` (CREDENTIAL_UNSAFE, CREDENTIAL_UNSUPPORTED);
   * the caller then closes the connection.
   */
  const prepareRotation = async (): Promise<Rotation | null> => {
    const current = secrets.credential;
    const refuse = (status: 'blocked' | 'failed', code: string, message: string) => {
      emit(status, { code, message });
      return null;
    };
    if (!current?.password) {
      return refuse(
        'failed',
        'CREDENTIAL_UNSUPPORTED',
        'Only a password credential can be rotated; nothing was changed.',
      );
    }
    const received = await guard(h.requestCredential('new'));
    if (!received?.password) {
      throw new ExecFail('CREDENTIAL_UNAVAILABLE', 'failed', 'credential_unavailable');
    }
    secrets.next = received;
    const user = current.username || init.username;
    if ((received.username || init.username) !== user) {
      return refuse(
        'blocked',
        'CREDENTIAL_MISMATCH',
        'The new credential belongs to another user; nothing was changed.',
      );
    }
    const userOk = DEVICE_USER.test(user) &&
      (dialect === 'linux' || dialect === 'proxmox' ? LINUX_USER.test(user) : true);
    if (
      !userOk || !NEW_PASSWORD.test(received.password) || received.password === current.password
    ) {
      return refuse(
        'failed',
        'CREDENTIAL_UNSAFE',
        'The new credential is not acceptable; nothing was changed.',
      );
    }
    return { user, password: received.password };
  };

  const rotationSteps = (r: Rotation): ChangeStep[] =>
    dialect === 'routeros'
      ? [{
        command: `/user set [find name="${r.user}"] password="${r.password}"`,
        display: '/user set [find name="' + r.user + '"] password=' + REDACTED_MARK,
      }]
      : [
        { command: 'aaa' },
        {
          command: `local-user ${r.user} password irreversible-cipher ${r.password}`,
          display: 'local-user ' + r.user + ' password irreversible-cipher ' + REDACTED_MARK,
        },
        { command: 'quit' },
      ];

  // --- settle: which password works once the request ended (rotation) ---------------------------

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  /** A fresh login with one credential: logged in, refused, or not decidable. */
  const tryLogin = async (credential: WorkerCredential): Promise<'ok' | 'refused' | 'error'> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let connection: { destroy(): void } | null = null;
    try {
      connection = await Promise.race([
        connect('probe', '', credential),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new ExecFail('CONNECT_FAILED')), SETTLE_LOGIN_MS);
        }),
      ]);
      return 'ok';
    } catch (error) {
      return error instanceof ExecFail && error.code === 'AUTH_FAILED' ? 'refused' : 'error';
    } finally {
      clearTimeout(timer);
      connection?.destroy();
    }
  };

  const whichPasswordWorks = async (): Promise<'new' | 'current' | 'unknown'> => {
    if (!secrets.next || !secrets.credential) return 'unknown';
    const withNew = await tryLogin(secrets.next);
    const withCurrent = await tryLogin(secrets.credential);
    if (withNew === 'ok' && withCurrent === 'refused') return 'new';
    if (withCurrent === 'ok' && withNew === 'refused') return 'current';
    return 'unknown';
  };

  let settled = false;
  /** Sends the result of a rotation after checking the device (never logs a password). */
  const settle = async () => {
    if (!rotation || settled) return;
    settled = true;
    let active: 'new' | 'current' | 'unknown' = 'unknown';
    try {
      const hint = rstate.hint;
      if (result.status === 'applied') active = 'new';
      else if (!rstate.loggedIn) active = 'unknown';
      else if (!rstate.changeMayHaveRun) active = 'current';
      else if (hint.kind === 'vrp') {
        active = hint.saved === true ? 'new' : hint.saved === false ? 'current' : 'unknown';
      } else if (hint.kind === 'ros') {
        await sleep(ROS_SETTLE_MS);
        active = await whichPasswordWorks();
      } else if (hint.kind === 'timer') {
        const until = hint.armedAt + exec.rollbackSeconds * 1000 + TIMER_MARGIN_MS;
        // The timer may still fire: only wait for it when that fits the budget.
        if (until - Date.now() <= SETTLE_BUDGET_MS) {
          for (;;) {
            active = await whichPasswordWorks();
            if (active === 'current' || Date.now() >= until) break;
            await sleep(Math.max(1, Math.min(SETTLE_POLL_MS, until - Date.now())));
          }
          result.rollback = active === 'current'
            ? { method: 'deadman_timer', armed: false, fired: true, pendingReboot: false }
            : { ...result.rollback, armed: Date.now() < until };
        }
      } else active = await whichPasswordWorks();
    } catch {
      active = 'unknown';
    }
    if (active === 'new' && result.status !== 'applied') {
      // The device runs the new password: the vault must follow; the error stays as a warning.
      result.status = 'applied';
      result.error = {
        code: result.error?.code ?? 'ROTATION_SETTLED',
        message: 'The new credential is active on the device.',
      };
    }
    result.credentialActive = active;
    sendResult();
  };

  const plainSteps = (): ChangeStep[] => exec.steps.map((command) => ({ command }));

  // --- flows ------------------------------------------------------------------------------------

  const readExecChannel = async () => {
    const conn = await connectFirst('');
    const client = raw(conn);
    for (const command of exec.steps) await runChannel(client, 'step', command);
    conn.end();
    emit('ok');
  };

  const readShell = async () => {
    const conn = await connectFirst('');
    const shell = await openShell(raw(conn), (view) => VRP_PROMPT.test('\n' + lastLineOf(view)));
    if (!(await guard(shell.waitPrompt(PROMPT_TIMEOUT_MS)))) throw new ExecFail('PROMPT_TIMEOUT');
    await runInShell(shell, 'screen-length 0 temporary', COMMAND_TIMEOUT_MS, null);
    for (const command of exec.steps) {
      const { run } = await runShell(shell, 'step', command, COMMAND_TIMEOUT_MS, 'N');
      if (run.timedOut) {
        conn.destroy();
        emit('failed', {
          code: 'COMMAND_TIMEOUT',
          message: 'A command did not return to the prompt.',
        });
        return;
      }
    }
    conn.end();
    emit('ok');
  };

  const routerosChange = async () => {
    const backup = exec.backupName!;
    const conn = await connectFirst('+ct4096w');
    let safeModeOn = false;
    let armedAt = 0;
    const rollBackBySocket = (code: string, message: string) => {
      // Dropping the connection (no logout) makes RouterOS undo everything done in safe mode.
      conn.destroy();
      result.rollback = { method: 'safe_mode', armed: true, fired: true, pendingReboot: false };
      emit('rolled_back', { code, message });
    };
    try {
      let steps = plainSteps();
      if (rotation) {
        const rot = await prepareRotation();
        if (!rot) {
          conn.end();
          return;
        }
        steps = rotationSteps(rot);
      }
      const shell = await openShell(
        raw(conn),
        (view) => ROS_PROMPT.test(lastLineOf(view)),
        4096,
      );
      if (!(await guard(shell.waitPrompt(PROMPT_TIMEOUT_MS)))) throw new ExecFail('PROMPT_TIMEOUT');
      // 1. backup before the change (outside safe mode)
      const backupCommand = `/export file=${backup}`;
      const backupRun = await runShell(shell, 'system', backupCommand, EXPORT_TIMEOUT_MS, null);
      if (backupRun.run.timedOut || ROS_ERROR.test(backupRun.output)) {
        conn.end();
        emit('failed', {
          code: 'BACKUP_FAILED',
          message: 'The configuration backup failed; nothing was changed.',
        });
        return;
      }
      // 2. take safe mode (Ctrl-X)
      shell.take();
      shell.send('\x18');
      const taken = await guard(
        shell.waitFor(
          (view) => /<SAFE>/.test(lastLineOf(view)) || /Safe mode taken/i.test(view),
          10000,
        ),
      );
      const settled = taken !== null && await guard(
        shell.waitFor(
          (view) => ROS_PROMPT.test(lastLineOf(view)) && /<SAFE>/.test(lastLineOf(view)),
          5000,
        ),
      );
      record('system', 'safe-mode take (Ctrl-X)', null, taken ? 'Safe mode taken' : '', false, 0);
      if (!settled) {
        conn.end();
        emit('failed', {
          code: 'SAFE_MODE_UNAVAILABLE',
          message: 'Safe mode could not be taken; nothing was changed.',
        });
        return;
      }
      safeModeOn = true;
      armedAt = Date.now();
      result.rollback = { method: 'safe_mode', armed: true, fired: false, pendingReboot: false };
      rstate.hint = { kind: 'ros' };
      // 3. the steps
      rstate.changeMayHaveRun = true;
      for (const { command, display } of steps) {
        if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
          rollBackBySocket('DEADLINE', 'The time budget of the change ran out; it was reverted.');
          return;
        }
        const { run, output } = await runShell(
          shell,
          'step',
          command,
          STEP_TIMEOUT_MS,
          null,
          display,
        );
        if (run.timedOut || run.unexpectedConfirm || ROS_ERROR.test(output)) {
          rollBackBySocket('STEP_FAILED', 'A step failed; safe mode reverted the changes.');
          return;
        }
      }
      // 4. verification in a NEW session; release (commit) only when it passes
      if (!(await verifyNewSession())) {
        rollBackBySocket(
          'VERIFY_FAILED',
          'The verification failed; safe mode reverted the changes.',
        );
        return;
      }
      if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
        rollBackBySocket('DEADLINE', 'The time budget of the change ran out; it was reverted.');
        return;
      }
      shell.take();
      shell.send('\x18');
      const released = await guard(
        shell.waitFor(
          (view) => ROS_PROMPT.test(lastLineOf(view)) && !/<SAFE>/.test(lastLineOf(view)),
          10000,
        ),
      );
      if (released === null) {
        // Ctrl-X was sent but the prompt never came back: the commit may or may not have happened.
        conn.destroy();
        result.rollback = { method: 'safe_mode', armed: true, fired: true, pendingReboot: false };
        emit('failed', {
          code: 'RELEASE_UNCERTAIN',
          message: 'Safe mode release was not confirmed; the device state must be checked.',
        });
        return;
      }
      safeModeOn = false; // committed from here on
      rstate.hint = { kind: 'none' };
      result.rollback = { method: 'safe_mode', armed: false, fired: false, pendingReboot: false };
      record('system', 'safe-mode release (Ctrl-X)', null, 'Safe mode released', false, 0);
      // 5. change log and post-change export. The change is committed: nothing below can turn it
      // into a failure, only into a note on the `applied` result.
      let documentation: ExecResult['error'] = null;
      let stage: 'changelog' | 'export' = 'changelog';
      try {
        if (exec.changeLog?.kind === 'script') {
          const ensure =
            ':if ([:len [/system script find name=mnscloud-changelog]]=0) do={/system script add name=mnscloud-changelog policy="" comment="MNSCloud: Registro de alteracoes do suporte (somente documentacao)" source="# Registro de alteracoes"}';
          const append =
            `/system script set [find name=mnscloud-changelog] source=([get [find name=mnscloud-changelog] source] . "\\n# ${exec.changeLog.line}")`;
          for (const command of [ensure, append]) {
            const r = await runShell(shell, 'system', command, STEP_TIMEOUT_MS, null);
            if (r.run.timedOut || ROS_ERROR.test(r.output)) {
              documentation = {
                code: 'CHANGELOG_FAILED',
                message: 'The change was applied; the change log line was not written.',
              };
              break;
            }
          }
        }
        stage = 'export';
        const after = `pos-${backup.replace(/^pre-/, '')}`;
        const exported = await runShell(
          shell,
          'system',
          `/export file=${after}`,
          EXPORT_TIMEOUT_MS,
          null,
        );
        if ((exported.run.timedOut || ROS_ERROR.test(exported.output)) && !documentation) {
          documentation = {
            code: 'EXPORT_FAILED',
            message: 'The change was applied; the post-change export failed.',
          };
        }
        shell.send('/quit\r');
        await shell.waitFor(() => false, 1000);
      } catch (error) {
        conn.destroy();
        emit('applied', {
          code: error instanceof ExecAbort
            ? 'EXEC_ABORTED'
            : stage === 'export'
            ? 'EXPORT_FAILED'
            : 'CHANGELOG_FAILED',
          message: 'The change was applied; the documentation step did not finish.',
        });
        if (error instanceof ExecAbort) throw error;
        return;
      }
      conn.end();
      emit('applied', documentation);
    } catch (error) {
      if (safeModeOn) {
        const reason = error instanceof ExecAbort ? error.reason : 'error';
        rollBackBySocket(
          error instanceof ExecAbort ? 'EXEC_ABORTED' : 'CONNECTION_LOST',
          `The request ended (${reason}) in safe mode; the device reverts the changes.`,
        );
        if (error instanceof ExecAbort) throw error;
        return;
      }
      conn.destroy();
      throw error;
    }
  };

  const vrpChange = async () => {
    const backup = exec.backupName!;
    const conn = await connectFirst('');
    let scheduled = false;
    let armedAt = 0;
    try {
      let steps = plainSteps();
      if (rotation) {
        const rot = await prepareRotation();
        if (!rot) {
          conn.end();
          return;
        }
        steps = rotationSteps(rot);
      }
      const shell = await openShell(raw(conn), (view) => VRP_PROMPT.test('\n' + lastLineOf(view)));
      if (!(await guard(shell.waitPrompt(PROMPT_TIMEOUT_MS)))) throw new ExecFail('PROMPT_TIMEOUT');
      await runInShell(shell, 'screen-length 0 temporary', COMMAND_TIMEOUT_MS, null);
      const system = async (command: string) => {
        const { run, output } = await runShell(shell, 'system', command, STEP_TIMEOUT_MS, 'Y');
        return !(run.timedOut || VRP_ERROR.test(output));
      };
      if (rotation) {
        // Only a local user can be rotated here (AAA/remote users have no local password).
        const user = secrets.credential!.username || init.username;
        const probe = `display local-user username ${user}`;
        const { run, output } = await runShell(shell, 'system', probe, COMMAND_TIMEOUT_MS, null);
        const listed = output.split(/[\s:]+/).includes(user);
        if (run.timedOut || VRP_ERROR.test(output) || !listed) {
          conn.end();
          emit('failed', {
            code: 'CREDENTIAL_UNSUPPORTED',
            message: 'The user is not a local user of the device; nothing was changed.',
          });
          return;
        }
      }
      if (!(await system(`save ${backup}.cfg`))) {
        conn.end();
        emit('failed', {
          code: 'BACKUP_FAILED',
          message: 'The configuration backup failed; nothing was changed.',
        });
        return;
      }
      const minutes = String(Math.ceil(exec.rollbackSeconds / 60)).padStart(2, '0');
      armedAt = Date.now(); // the delay starts when the device accepts the command
      if (!(await system(`schedule reboot delay 00:${minutes}`))) {
        conn.end();
        emit('failed', {
          code: 'SCHEDULE_FAILED',
          message: 'The rollback reboot could not be scheduled; nothing was changed.',
        });
        return;
      }
      scheduled = true;
      result.rollback = {
        method: 'scheduled_reboot',
        armed: true,
        fired: false,
        pendingReboot: false,
      };
      if (rotation) rstate.hint = { kind: 'vrp', saved: false };
      const rollbackNow = (code: string, message: string) => {
        // The device reboots into the saved configuration when the delay ends.
        conn.end();
        result.rollback = {
          method: 'scheduled_reboot',
          armed: true,
          fired: false,
          pendingReboot: true,
        };
        emit('rolled_back', { code, message });
      };
      rstate.changeMayHaveRun = true;
      let failed = !(await system('system-view'));
      for (const { command, display } of failed ? [] : steps) {
        if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
          rollbackNow('DEADLINE', 'The time budget of the change ran out; the device reboots.');
          return;
        }
        const { run, output } = await runShell(
          shell,
          'step',
          command,
          STEP_TIMEOUT_MS,
          'N',
          display,
        );
        if (run.timedOut || run.unexpectedConfirm || VRP_ERROR.test(output)) {
          failed = true;
          break;
        }
      }
      if (failed) {
        rollbackNow(
          'STEP_FAILED',
          'A step failed; the device reboots into the saved configuration.',
        );
        return;
      }
      await runShell(shell, 'system', 'return', COMMAND_TIMEOUT_MS, null);
      if (!(await verifyNewSession())) {
        rollbackNow(
          'VERIFY_FAILED',
          'The verification failed; the device reboots into the saved configuration.',
        );
        return;
      }
      if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
        rollbackNow('DEADLINE', 'The time budget of the change ran out; the device reboots.');
        return;
      }
      if (rotation) {
        // Save first: from the save on, the new password is the startup configuration and every
        // later problem leaves it applied. A failed save keeps the reboot armed (back to current).
        rstate.hint = { kind: 'vrp', saved: null };
        const saved = await runShell(shell, 'system', 'save', STEP_TIMEOUT_MS, 'Y');
        const savedOk = !(saved.run.timedOut || VRP_ERROR.test(saved.output));
        if (!savedOk) {
          rstate.hint = { kind: 'vrp', saved: saved.run.timedOut ? null : false };
          rollbackNow(
            'SAVE_FAILED',
            'The new password was not saved; the device reboots into the saved configuration.',
          );
          return;
        }
        rstate.hint = { kind: 'vrp', saved: true };
        const undone = await system('undo schedule reboot');
        scheduled = false;
        if (!undone) {
          // Saved: a reboot reloads the new password. Report it as applied, reboot still armed.
          conn.end();
          result.rollback = {
            method: 'scheduled_reboot',
            armed: true,
            fired: false,
            pendingReboot: true,
          };
          emit('applied', {
            code: 'CANCEL_FAILED',
            message: 'The new password is saved; the scheduled reboot could not be cancelled.',
          });
          return;
        }
        result.rollback = {
          method: 'scheduled_reboot',
          armed: false,
          fired: false,
          pendingReboot: false,
        };
        conn.end();
        emit('applied');
        return;
      }
      const cancelled = await system('undo schedule reboot');
      if (!cancelled) {
        // The reboot may still fire: report it so nobody believes the change is permanent.
        rollbackNow(
          'CANCEL_FAILED',
          'The scheduled reboot could not be cancelled; it may revert the change.',
        );
        return;
      }
      scheduled = false;
      result.rollback = {
        method: 'scheduled_reboot',
        armed: false,
        fired: false,
        pendingReboot: false,
      };
      if (!(await system('save'))) {
        conn.end();
        emit('failed', {
          code: 'SAVE_FAILED',
          message: 'The change is running but was not saved.',
        });
        return;
      }
      conn.end();
      emit('applied');
    } catch (error) {
      if (rotation && rstate.hint.kind === 'vrp' && rstate.hint.saved === true) {
        // The new password was saved before the request ended: it is applied.
        conn.end();
        result.rollback = {
          method: 'scheduled_reboot',
          armed: scheduled,
          fired: false,
          pendingReboot: scheduled,
        };
        emit('applied', {
          code: error instanceof ExecAbort ? 'EXEC_ABORTED' : 'CONNECTION_LOST',
          message: 'The new password is saved; the request ended before the reboot was cancelled.',
        });
        if (error instanceof ExecAbort) throw error;
        return;
      }
      if (scheduled) {
        // Nothing was committed: the pending reboot returns the device to the saved configuration.
        conn.end();
        result.rollback = {
          method: 'scheduled_reboot',
          armed: true,
          fired: false,
          pendingReboot: true,
        };
        if (error instanceof ExecAbort) {
          emit('rolled_back', {
            code: 'EXEC_ABORTED',
            message: 'The request ended before the commit.',
          });
        } else {
          emit('rolled_back', {
            code: 'CONNECTION_LOST',
            message: 'The connection was lost before the commit.',
          });
          return;
        }
      } else conn.destroy();
      throw error;
    }
  };

  const linuxChange = async () => {
    const unit = `mns-rb-${hex}`;
    const conn = await connectFirst('');
    const client = raw(conn);
    let armed = false;
    let armedAt = 0;
    let scriptWritten = false;
    let removeScriptQuietly = async () => {};
    try {
      const uidRun = await runChannel(client, 'system', 'id -u');
      const uid = Number.parseInt(uidRun.output.trim(), 10);
      if (uidRun.exitCode !== 0 || !Number.isInteger(uid)) {
        conn.end();
        emit('failed', {
          code: 'IDENTITY_UNKNOWN',
          message: 'The remote user could not be determined; nothing was changed.',
        });
        return;
      }
      const asRoot = (command: string) =>
        uid === 0 ? command : `sudo -n /bin/sh -c ${shellQuote(command)}`;
      verifyWire = asRoot;
      // Rotation: the new credential is checked, the current hash is kept in memory and written
      // (stdin only, never argv) into a root-only rollback script the dead-man timer runs.
      const scriptFile = `/run/${unit}.sh`;
      const removeScript = async (): Promise<boolean> => {
        const remove = `rm -f ${scriptFile}`;
        const removed = await runChannel(client, 'system', remove, asRoot(remove));
        return removed.exitCode === 0;
      };
      removeScriptQuietly = async () => {
        try {
          await removeScript();
        } catch { /* connection gone: the script is root-only and self-deleting */ }
      };
      let rot: Rotation | null = null;
      if (rotation) {
        rot = await prepareRotation();
        if (!rot) {
          conn.end();
          return;
        }
        const getent = `getent shadow ${rot.user}`;
        const started = Date.now();
        const shadow = await guard(execChannel(client, asRoot(getent), COMMAND_TIMEOUT_MS));
        // The shadow line is a secret: only the exit code is recorded.
        record('system', getent, shadow.exitCode, '', false, Date.now() - started);
        if (shadow.lost) throw new ExecFail('CONNECTION_LOST');
        const fields = shadow.raw.split('\n')[0].split(':');
        const hash = fields[0] === rot.user ? fields[1] ?? '' : '';
        if (shadow.exitCode !== 0 || !SHADOW_HASH.test(hash)) {
          conn.end();
          emit('failed', {
            code: 'SHADOW_UNAVAILABLE',
            message: 'The current password hash could not be read; nothing was changed.',
          });
          return;
        }
        redactor.addSecret(hash);
        // The script removes itself after it ran, whatever chpasswd returned.
        const install = `umask 077; install -m 600 /dev/stdin ${scriptFile}`;
        const content =
          `chpasswd -e <<'EOF'\n${rot.user}:${hash}\nEOF\nrc=$?\nrm -f -- ${scriptFile}\nexit $rc\n`;
        const written = await runChannel(
          client,
          'system',
          install,
          asRoot(install),
          COMMAND_TIMEOUT_MS,
          content,
        );
        scriptWritten = true;
        if (written.exitCode !== 0) {
          await removeScript();
          conn.end();
          emit('failed', {
            code: 'ROLLBACK_SCRIPT_FAILED',
            message: 'The rollback script could not be written; nothing was changed.',
          });
          return;
        }
      }
      const script = Buffer.from(exec.rollback.join('\n'), 'utf8').toString('base64');
      const unitCommand = rotation
        ? `/bin/sh ${scriptFile}`
        : `/bin/sh -c ${shellQuote(`echo ${script} | base64 -d | /bin/sh`)}`;
      const arm =
        `systemd-run --unit=${unit} --on-active=${exec.rollbackSeconds} --timer-property=AccuracySec=1s --property=Type=oneshot --property=TimeoutStartSec=120 ${unitCommand}`;
      armedAt = Date.now(); // the timer counts from the moment the device accepts the command
      const armed_ = await runChannel(client, 'system', arm, asRoot(arm));
      if (armed_.exitCode !== 0) {
        if (rotation) await removeScript();
        conn.end();
        emit('failed', {
          code: 'ARM_FAILED',
          message: 'The rollback timer could not be armed; nothing was changed.',
        });
        return;
      }
      armed = true;
      if (rotation) rstate.hint = { kind: 'timer', armedAt };
      result.rollback = {
        method: 'deadman_timer',
        armed: true,
        fired: false,
        pendingReboot: false,
      };
      const rollbackNow = async (code: string, message: string) => {
        const start = `systemctl start ${unit}.service`;
        const stop = `systemctl stop ${unit}.timer`;
        const started = await runChannel(client, 'rollback', start, asRoot(start), 130000);
        if (started.exitCode !== 0) {
          // The rollback script did not run: keep the timer armed, it is the last safety net.
          conn.end();
          result.rollback = {
            method: 'deadman_timer',
            armed: true,
            fired: false,
            pendingReboot: false,
          };
          emit('failed', {
            code: 'ROLLBACK_FAILED',
            message: 'The rollback commands failed; the timer stays armed.',
          });
          return;
        }
        await runChannel(client, 'rollback', stop, asRoot(stop));
        if (rotation) {
          rstate.hint = { kind: 'none' }; // the script ran: the old hash is back
          await removeScript();
        }
        conn.end();
        result.rollback = {
          method: 'deadman_timer',
          armed: false,
          fired: true,
          pendingReboot: false,
        };
        emit('rolled_back', { code, message });
      };
      const linuxSteps: { command: string; stdin?: string }[] = rot
        ? [{ command: 'chpasswd', stdin: `${rot.user}:${rot.password}\n` }]
        : plainSteps();
      for (const { command, stdin } of linuxSteps) {
        if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
          await rollbackNow('DEADLINE', 'The time budget of the change ran out; rolled back.');
          return;
        }
        if (rotation) rstate.changeMayHaveRun = true;
        const r = await runChannel(
          client,
          'step',
          command,
          asRoot(command),
          STEP_TIMEOUT_MS,
          stdin,
        );
        if (r.exitCode !== 0) {
          await rollbackNow('STEP_FAILED', 'A step failed; the rollback commands were run.');
          return;
        }
      }
      if (!(await verifyNewSession())) {
        await rollbackNow(
          'VERIFY_FAILED',
          'The verification failed; the rollback commands were run.',
        );
        return;
      }
      if (deadlineExceeded(armedAt, Date.now(), exec.rollbackSeconds)) {
        await rollbackNow('DEADLINE', 'The time budget of the change ran out; rolled back.');
        return;
      }
      const stop = `systemctl stop ${unit}.timer`;
      const disarm = await runChannel(client, 'system', stop, asRoot(stop));
      if (disarm.exitCode !== 0) {
        conn.end();
        result.rollback = {
          method: 'deadman_timer',
          armed: true,
          fired: false,
          pendingReboot: false,
        };
        emit('failed', {
          code: 'DEADMAN_DISARM_FAILED',
          message: 'The rollback timer could not be stopped; it may revert the change.',
        });
        return;
      }
      armed = false;
      if (rotation) rstate.hint = { kind: 'none' };
      result.rollback = {
        method: 'deadman_timer',
        armed: false,
        fired: false,
        pendingReboot: false,
      };
      let documentation: ExecResult['error'] = null;
      try {
        if (rotation && !(await removeScript())) {
          documentation = {
            code: 'ROLLBACK_SCRIPT_REMAINS',
            message: 'The change was applied; the root-only rollback script was not removed.',
          };
        }
        if (exec.changeLog?.kind === 'file') {
          const line = `printf '%s\\n' '${exec.changeLog.line}' >> /etc/mnscloud-changelog`;
          const written = await runChannel(client, 'system', line, asRoot(line));
          if (written.exitCode !== 0 && !documentation) {
            documentation = {
              code: 'CHANGELOG_FAILED',
              message: 'The change was applied; the change log line was not written.',
            };
          }
        }
      } catch (error) {
        // Committed (timer stopped): only the documentation is lost.
        conn.destroy();
        emit('applied', {
          code: error instanceof ExecAbort ? 'EXEC_ABORTED' : 'CHANGELOG_FAILED',
          message: 'The change was applied; the change log line was not written.',
        });
        if (error instanceof ExecAbort) throw error;
        return;
      }
      conn.end();
      emit('applied', documentation);
    } catch (error) {
      if (armed) {
        // The timer fires by itself: the change reverts without any further action.
        conn.destroy();
        result.rollback = {
          method: 'deadman_timer',
          armed: true,
          fired: false,
          pendingReboot: false,
        };
        emit('failed', {
          code: error instanceof ExecAbort ? 'EXEC_ABORTED' : 'CONNECTION_LOST',
          message: 'The request ended before the commit; the rollback timer reverts the change.',
        });
        if (error instanceof ExecAbort) throw error;
        return;
      }
      if (scriptWritten) {
        // Nothing was armed: do not leave the root-only script behind (best effort).
        await removeScriptQuietly();
      }
      conn.destroy();
      throw error;
    }
  };

  // --- dispatch --------------------------------------------------------------------------------

  let finish: Exit | null = null;
  try {
    if (exec.kind === 'read') {
      if (dialect === 'vrp') await readShell();
      else await readExecChannel();
    } else if (exec.safeChange === 'routeros_safe_mode') await routerosChange();
    else if (exec.safeChange === 'vrp5_schedule_reboot') await vrpChange();
    else await linuxChange();
    await settle();
    finish = h.finish('closed', 'exec_done');
  } catch (error) {
    for (const client of clients) client.destroy();
    if (error instanceof ExecAbort) {
      if (!result.error) {
        emit('failed', { code: 'EXEC_ABORTED', message: 'The request was cancelled.' });
      }
      await settle();
      finish = h.finish(
        'closed',
        error.reason === 'controller_gone' ? 'gateway_closed' : error.reason,
      );
    } else if (error instanceof ExecFail) {
      emit('failed', { code: error.code, message: error.code });
      await settle();
      finish = error.state === 'failed' && error.reason === 'exec_done'
        ? h.finish('closed', 'exec_done')
        : h.finish(error.state, error.reason);
    } else {
      emit('failed', { code: 'EXEC_INTERNAL', message: 'The request failed unexpectedly.' });
      await settle();
      finish = h.finish('failed', 'device_error');
    }
  } finally {
    secrets.credential = null;
    secrets.next = null;
    for (const client of clients) client.end();
  }
  return finish!;
}
