// WinRM sessions of the worker (Windows dialect): access test with true console readiness, the
// manual console (one cmd line at a time through the input gate, classifier, confirmation,
// redaction and recording) and exec reads for the AI copilot. Never a local shell, never PowerShell
// remoting: see `winrm.ts` for the transport rules.

import { AsciicastWriter } from '../shared/asciicast.ts';
import type { ExecResult, ExecStatus } from '../shared/exec.ts';
import type { ControlMessage } from '../shared/framing.ts';
import type {
  ControllerToWorker,
  WorkerCredential,
  WorkerInit,
  WorkerToController,
} from '../shared/ipc.ts';
import { Classifier } from './classifier.ts';
import { cleanOutput, fitResult, OUTPUT_CAP_BYTES, planExec } from './exec.ts';
import { InputGate } from './input_gate.ts';
import type { Redactor } from './redaction.ts';
import { connectApiSsl, type RouterOsApiError } from './routeros_api.ts';
import type { DialectRules } from './rules.ts';
import { OutputLimiter, TerminalSanitizer } from './terminal.ts';
import {
  basicAuthorization,
  hostAuthority,
  HttpConnection,
  runWinrmCommand,
  WinrmError,
  WsmanClient,
} from './winrm.ts';

type Exit = Extract<WorkerToController, { t: 'exit' }>;

export const WINRM_COMMAND_TIMEOUT_MS = 20000;

export interface WinrmHelpers {
  init: WorkerInit;
  rules: DialectRules;
  redactor: Redactor;
  verifyKey(
    kind: 'ssh' | 'tls',
    algorithm: string,
    fingerprint: string,
    pinned: string | null,
  ): Promise<boolean>;
  requestCredential(): Promise<WorkerCredential | null>;
  send(message: WorkerToController): void;
  control(m: ControlMessage): void;
  finish(state: Exit['state'], reason: string): Exit;
  onClose(handler: (reason: string) => void): void;
  onMessage(handler: (message: ControllerToWorker) => void): void;
  counters: { in(n: number): void; out(n: number): void };
}

/** A failure that ends the session with a finish state and reason. */
class SessionFail extends Error {
  constructor(readonly state: Exit['state'], readonly reason: string) {
    super(reason);
  }
}

interface Open {
  client: WsmanClient;
  http: HttpConnection;
  shellId: string;
  /** Best effort: Delete the shell (bounded) and close the connection. */
  close(): Promise<void>;
}

/**
 * TLS, pin decision, credential, then Create. Order matters: the pin is decided on the raw TLS
 * connection before the credential is even requested, so a mismatch never sees a password.
 */
async function open(h: WinrmHelpers, signal: AbortSignal): Promise<Open> {
  const check = () => {
    if (signal.aborted) throw new SessionFail('closed', 'cancelled');
  };
  check();
  const { init } = h;
  h.control({ type: 'state', state: 'connecting' });
  let connection;
  try {
    connection = await connectApiSsl(
      init.target.address,
      init.target.port,
      init.limits.connectTimeoutSeconds * 1000,
      init.transport === 'connector'
        ? { path: init.bridge!, secret: init.bridgeSecret! }
        : undefined,
    );
  } catch (error) {
    check();
    const code = (error as RouterOsApiError).code;
    throw new SessionFail('failed', code === 'tls_failed' ? 'tls_failed' : 'connect_failed');
  }
  const abort = () => connection.transport.close();
  signal.addEventListener('abort', abort, { once: true });
  try {
    check();
    if (!(await h.verifyKey('tls', 'x509', connection.pin, init.tls.pinned))) {
      connection.transport.close();
      throw new SessionFail('refused', init.tls.pinned ? 'hostkey_mismatch' : 'hostkey_rejected');
    }
    check();
    h.control({ type: 'state', state: 'authenticating' });
    check();
    const credential = await h.requestCredential();
    if (signal.aborted) {
      if (credential) {
        credential.password = '';
      }
      check();
    }
    const username = credential?.username || init.username;
    // Basic cannot carry ':' in the user name; control characters never belong in a header.
    // deno-lint-ignore no-control-regex
    if (!credential?.password || /[:\x00-\x1f\x7f]/.test(username)) {
      connection.transport.close();
      throw new SessionFail('failed', 'credential_unavailable');
    }
    const authority = hostAuthority(init.target.address, init.target.port);
    const http = new HttpConnection(
      connection.transport,
      authority,
      basicAuthorization(username, credential.password),
    );
    credential.password = '';
    const client = new WsmanClient(http, `https://${authority}/wsman`);
    let shellId: string;
    try {
      check();
      shellId = await client.createShell();
      check();
    } catch (error) {
      http.close();
      check();
      if (error instanceof WinrmError && error.code === 'auth_failed') {
        h.send({ t: 'credential_result', result: 'auth_failed' });
        throw new SessionFail('failed', 'auth_failed');
      }
      // The login may have worked but the shell could not be created (WinRS disabled, quotas):
      // the access is not ready, and the reason is a protocol one, not a credential one.
      throw new SessionFail(
        'failed',
        error instanceof WinrmError && error.code === 'timeout'
          ? 'connect_failed'
          : 'protocol_error',
      );
    }
    h.send({ t: 'credential_result', result: 'used' });
    signal.removeEventListener('abort', abort);
    let closed = false;
    return {
      client,
      http,
      shellId,
      close: async () => {
        if (closed) return;
        closed = true;
        if (http.usable) {
          await client.deleteShell(shellId).catch(() => {});
        }
        http.close();
      },
    };
  } catch (error) {
    signal.removeEventListener('abort', abort);
    connection.transport.close();
    check();
    throw error;
  }
}

function failureOf(error: unknown): { state: Exit['state']; reason: string } {
  if (error instanceof SessionFail) return { state: error.state, reason: error.reason };
  const reason = error instanceof WinrmError && error.code === 'timeout'
    ? 'connect_failed'
    : 'protocol_error';
  return { state: 'failed', reason };
}

function failExit(h: WinrmHelpers, error: unknown): Exit {
  const { state, reason } = failureOf(error);
  return h.finish(state, reason);
}

// ---------------------------------------------------------------------------------------------
// Access test: login AND a created (then deleted) WinRS shell = the console would be ready.

export async function winrmTest(h: WinrmHelpers): Promise<Exit> {
  const cancel = new AbortController();
  h.onClose(() => cancel.abort());
  let session: Open | null = null;
  try {
    session = await open(h, cancel.signal);
    await session.close();
    session = null;
    if (cancel.signal.aborted) return h.finish('closed', 'cancelled');
    h.send({ t: 'facts', facts: {} });
    return h.finish('closed', 'test_ok');
  } catch (error) {
    await session?.close();
    return failExit(h, error);
  }
}

// ---------------------------------------------------------------------------------------------
// Exec (AI copilot): reads only. Changes and rotations are blocked by the payload contract and
// again here.

export async function winrmExec(h: WinrmHelpers): Promise<Exit> {
  const { init, redactor, rules } = h;
  const exec = init.exec!;
  const result: ExecResult = {
    status: 'failed',
    steps: [],
    rollback: { method: 'none', armed: false, fired: false, pendingReboot: false },
    error: null,
  };
  const emit = (status: ExecStatus, error: ExecResult['error'] = null) => {
    result.status = status;
    if (error) result.error = error;
    h.send({ t: 'exec_result', result: fitResult(result) });
  };
  if (exec.kind !== 'read') {
    emit('blocked', {
      code: 'EXEC_BLOCKED',
      message: 'Windows supports reads only; nothing was executed.',
    });
    return h.finish('closed', 'exec_done');
  }
  const planned = planExec(exec, rules, init.level);
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
    return h.finish('closed', 'exec_done');
  }
  let cancelled: string | null = null;
  const cancel = new AbortController();
  h.onClose((reason) => {
    cancelled = reason;
    cancel.abort();
  });
  let session: Open | null = null;
  try {
    session = await open(h, cancel.signal);
    for (const command of exec.steps) {
      const started = Date.now();
      const decoder = new TextDecoder();
      let raw = '';
      const run = await runWinrmCommand(session.client, session.shellId, command, {
        timeoutMs: WINRM_COMMAND_TIMEOUT_MS,
        maxBytes: OUTPUT_CAP_BYTES,
        onChunk: (chunk) => {
          raw += decoder.decode(chunk.bytes, { stream: true });
        },
        cancelled: () => cancelled !== null,
      });
      const plan = planned.items.find((i) => i.phase === 'step' && i.command === command);
      result.steps.push({
        phase: 'step',
        command: redactor.redactText(command),
        class: plan?.class ?? null,
        rule: plan?.rule ?? null,
        verdict: 'allowed',
        exitCode: run.timedOut ? 124 : run.exitCode,
        output: cleanOutput(redactor, raw, run.truncated),
        truncated: run.truncated,
        ms: Date.now() - started,
      });
      if (run.cancelled) {
        await session.close();
        emit('failed', { code: 'EXEC_ABORTED', message: 'The request was cancelled.' });
        return h.finish('closed', cancelled === 'controller_gone' ? 'gateway_closed' : cancelled!);
      }
      const problem = run.timedOut
        ? { code: 'COMMAND_TIMEOUT', message: 'A command did not finish in time.' }
        : run.truncated
        ? { code: 'OUTPUT_LIMIT', message: 'A command produced more output than allowed.' }
        : run.exitCode !== 0
        ? { code: 'COMMAND_FAILED', message: 'A command did not finish successfully.' }
        : null;
      if (problem) {
        await session.close();
        emit('failed', problem);
        return h.finish('closed', 'exec_done');
      }
    }
    await session.close();
    emit('ok');
    return h.finish('closed', 'exec_done');
  } catch (error) {
    await session?.close();
    if (error instanceof SessionFail) {
      // Nothing ran before the failure (pin, credential, auth, create): say why in the result.
      emit('failed', { code: error.reason.toUpperCase(), message: error.reason });
      return h.finish(error.state, error.reason);
    }
    const code = error instanceof WinrmError
      ? (error.code === 'fault'
        ? `WINRM_FAULT_${error.detail}`.slice(0, 60)
        : `WINRM_${error.code}`.toUpperCase())
      : 'EXEC_INTERNAL';
    emit('failed', { code, message: 'The WinRM request failed.' });
    return h.finish('failed', 'protocol_error');
  }
}

// ---------------------------------------------------------------------------------------------
// Console: a line-oriented terminal on top of WinRS. The browser terminal sends keystrokes, the
// gate reconstructs the line, classifies it and releases Enter; this adapter is the "device": it
// echoes, collects the line and runs it as ONE WinRS command. A line the adapter itself cannot
// trust (escape sequences, control characters, too long) is dropped, never run.

const MAX_LINE = 1024;
const PROMPT = '\r\n> ';

class LineDevice {
  #line = '';
  #dirty = false;
  running = false;
  #abort: (() => void) | null = null;

  constructor(
    private readonly emit: (text: string) => void,
    private readonly run: (line: string) => Promise<void>,
  ) {}

  setAbort(abort: (() => void) | null) {
    this.#abort = abort;
  }

  /** Data the gate released to the "device": typed characters, Enter, cancel keys. */
  write(data: string) {
    if (data.startsWith('\x1b')) {
      // Arrows, history, Tab completion, paste markers: the line is no longer what was classified.
      this.#dirty = true;
      return;
    }
    for (const ch of data) {
      if (ch === '\r') this.#submit();
      else if (ch === '\x15') this.#clear();
      else if (ch === '\x03') {
        this.#clear();
        if (this.running) this.#abort?.();
        else this.emit('^C' + PROMPT);
      } else if (ch === '\x7f' || ch === '\b') {
        if (this.#line.length) {
          this.#line = this.#line.slice(0, -1);
          this.emit('\b \b');
        }
      } else if (ch >= ' ' && ch !== '\x7f') {
        if (this.#line.length >= MAX_LINE) this.#dirty = true;
        else {
          this.#line += ch;
          this.emit(ch);
        }
      } else this.#dirty = true;
    }
  }

  #clear() {
    this.#line = '';
    this.#dirty = false;
  }

  #submit() {
    const line = this.#line;
    const dirty = this.#dirty;
    this.#clear();
    this.emit('\r\n');
    if (dirty) {
      this.emit('Line not executed (it cannot be reconstructed safely).' + PROMPT);
    } else if (!line.trim()) {
      this.emit('> ');
    } else if (this.running) {
      this.emit('A command is still running.' + PROMPT);
    } else {
      this.running = true;
      this.run(line).finally(() => {
        this.running = false;
      });
    }
  }
}

export function winrmConsole(h: WinrmHelpers): Promise<Exit> {
  const { init } = h;
  return new Promise<Exit>((resolve) => {
    let done = false;
    const cancel = new AbortController();
    let session: Open | null = null;
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    let idleTimer: ReturnType<typeof setInterval> | null = null;
    let lastActivity = Date.now();
    let cancelRequested = false;
    const sanitizer = new TerminalSanitizer();
    const decoder = new TextDecoder();
    const limiter = new OutputLimiter(
      init.limits.maxOutputBytesPerSecond,
      init.limits.maxOutputBytes,
    );
    const cast = init.recording
      ? new AsciicastWriter({
        width: init.terminal.cols,
        height: init.terminal.rows,
        timestamp: Math.floor(Date.now() / 1000),
      })
      : null;
    const emitCast = (line: string) => cast && h.send({ t: 'cast', line });
    const emitOutput = (text: string) => {
      if (!text) return;
      h.send({ t: 'output', d: text });
      if (cast) emitCast(cast.output(text));
    };
    const classifier = new Classifier(h.rules);
    const gate = new InputGate(classifier, init.level, {
      toDevice: (data) => {
        h.counters.out(new TextEncoder().encode(data).length);
        device.write(data);
      },
      control: h.control,
      event: (e) => h.send({ t: 'event', e }),
      marker: (label) => cast && emitCast(cast.marker(label)),
      redactLine: (line) => h.redactor.redactText(line),
    }, init.limits.verdictTimeoutSeconds);

    const end = async (state: Exit['state'], reason: string) => {
      if (done) return;
      done = true;
      cancel.abort();
      if (flushTimer) clearTimeout(flushTimer);
      if (idleTimer) clearInterval(idleTimer);
      gate.close();
      emitOutput(h.redactor.flush(true) + h.redactor.end());
      await session?.close();
      h.control({ type: 'state', state: state === 'closed' ? 'closed' : 'failed', reason });
      resolve(h.finish(state, reason));
    };

    // Echo and prompt are ours; device output goes through the sanitizer, gate and redactor.
    const echo = (text: string) => {
      lastActivity = Date.now();
      emitOutput(h.redactor.push(text));
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = setTimeout(() => emitOutput(h.redactor.flush()), 50);
    };

    const runLine = async (line: string) => {
      if (!session) return;
      cancelRequested = false;
      device.setAbort(() => {
        cancelRequested = true;
      });
      try {
        const run = await runWinrmCommand(session.client, session.shellId, line, {
          timeoutMs: init.limits.idleSeconds * 1000,
          maxBytes: 8 * 1024 * 1024,
          onChunk: (chunk) => {
            lastActivity = Date.now();
            h.counters.in(chunk.bytes.length);
            const { exceeded } = limiter.take(chunk.bytes.length);
            if (exceeded) {
              void end('closed', 'output_limit');
              return;
            }
            const text = sanitizer.push(decoder.decode(chunk.bytes, { stream: true }));
            gate.observeOutput(text);
            echo(text.replace(/\r?\n/g, '\r\n'));
          },
          cancelled: () => cancelRequested || done,
        });
        if (run.timedOut) echo('\r\n[command stopped: no end within the idle limit]');
        else if (run.truncated) echo('\r\n[output limit reached]');
        else if (run.cancelled && !done) echo('\r\n[command cancelled]');
      } catch (error) {
        // A transport error, a fault or a mismatch: the shell cannot be trusted any more.
        const reason = error instanceof WinrmError && error.code === 'closed'
          ? 'device_closed'
          : 'device_error';
        await end('failed', reason);
        return;
      } finally {
        device.setAbort(null);
      }
      if (!done) echo(PROMPT);
    };
    const device = new LineDevice(echo, runLine);

    h.onClose((reason) => {
      void end('closed', reason === 'controller_gone' ? 'gateway_closed' : reason);
    });
    h.onMessage((message) => {
      if (!session || done) return;
      if (message.t === 'input') {
        lastActivity = Date.now();
        gate.input(message.d);
      } else if (message.t === 'resize') {
        if (cast) emitCast(cast.resize(message.cols, message.rows));
      } else if (message.t === 'confirm') {
        gate.decide(message.m);
      }
    });

    open(h, cancel.signal).then((opened) => {
      if (done) {
        void opened.close();
        return;
      }
      session = opened;
      if (cast) emitCast(cast.headerLine());
      h.send({ t: 'ready' });
      h.control({ type: 'state', state: 'ready' });
      echo('Windows command shell (WinRS over WinRM). One command per line.' + PROMPT);
      idleTimer = setInterval(() => {
        if (Date.now() - lastActivity > init.limits.idleSeconds * 1000 && !device.running) {
          void end('closed', 'idle_timeout');
        }
      }, 5000);
    }).catch((error) => {
      if (done) return;
      done = true;
      gate.close();
      const { state, reason } = failureOf(error);
      h.control({ type: 'state', state: 'failed', reason });
      resolve(h.finish(state, reason));
    });
  });
}
