// One support connection, inside its sandbox (systemd-run transient unit, own network namespace,
// dynamic user, no capabilities, Deno --allow-net=<device ip>:<port>). It speaks exactly one
// device protocol, never runs a local program, and redacts everything before it leaves.

import { createHash } from 'node:crypto';
// @ts-types="../types/ssh2.d.ts"
import ssh2 from 'ssh2';
import { AsciicastWriter } from '../shared/asciicast.ts';
import type { ControlMessage } from '../shared/framing.ts';
import { parseAddress } from '../shared/ip.ts';
import type {
  ControllerToWorker,
  WorkerCredential,
  WorkerInit,
  WorkerToController,
} from '../shared/ipc.ts';
import { Classifier } from './classifier.ts';
import { InputGate } from './input_gate.ts';
import { Redactor } from './redaction.ts';
import { connectApiSsl, RouterOsApi, RouterOsApiError } from './routeros_api.ts';
import { DIALECTS, loadRules } from './rules.ts';
import { OutputLimiter, TerminalSanitizer } from './terminal.ts';

// deno-lint-ignore no-explicit-any
const { Client } = ssh2 as any;

export const REFUSED_PORTS = new Set([23, 8728]);
const FLUSH_MS = 50;

export interface WorkerIO {
  messages: AsyncIterable<unknown>;
  send(message: WorkerToController): void;
}

type Exit = Extract<WorkerToController, { t: 'exit' }>;

class WorkerExit extends Error {
  constructor(readonly state: Exit['state'], readonly reason: string) {
    super(reason);
  }
}

/** Strict validation of the init message: the worker trusts nothing it did not check. */
export function validateInit(value: unknown): WorkerInit {
  const v = value as WorkerInit;
  const ok = v && v.t === 'init' && /^[0-9a-f-]{36}$/.test(v.connectionUUID) &&
    (v.mode === 'console' || v.mode === 'test') &&
    (v.protocol === 'ssh' || v.protocol === 'routeros_api') &&
    parseAddress(v.target?.address) !== null && Number.isInteger(v.target?.port) &&
    v.target.port >= 1 && v.target.port <= 65535 && DIALECTS.includes(v.shellDialect) &&
    typeof v.username === 'string' && v.username.length <= 128 && !/[\r\n\0]/.test(v.username) &&
    ['n1', 'n2', 'n3'].includes(v.level) && v.terminal && v.limits;
  if (!ok) throw new WorkerExit('refused', 'invalid_assignment');
  if (REFUSED_PORTS.has(v.target.port)) throw new WorkerExit('refused', 'protocol_refused');
  if (v.protocol === 'routeros_api' && v.mode !== 'test') {
    throw new WorkerExit('refused', 'protocol_refused');
  }
  return v;
}

/** "SHA256:<base64>" of an SSH public key blob (OpenSSH format, as the API stores it). */
export function sshFingerprint(key: Uint8Array): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

export function sshKeyAlgorithm(key: Uint8Array): string {
  if (key.length < 4) return 'unknown';
  const length = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
  if (length <= 0 || length > 64 || key.length < 4 + length) return 'unknown';
  return new TextDecoder().decode(key.subarray(4, 4 + length));
}

/** One-shot waits for controller replies plus streaming handlers. */
class Mailbox {
  #waiters = new Map<string, (message: ControllerToWorker) => void>();
  #handlers: ((message: ControllerToWorker) => void)[] = [];
  #closed: ((reason: string) => void)[] = [];

  dispatch(message: ControllerToWorker) {
    if (message.t === 'close') {
      for (const handler of this.#closed) handler(message.reason);
      return;
    }
    const key = message.t === 'credential_unavailable' ? 'credential' : message.t;
    const waiter = this.#waiters.get(key);
    if (waiter) {
      this.#waiters.delete(key);
      waiter(message);
      return;
    }
    for (const handler of this.#handlers) handler(message);
  }

  wait<T extends ControllerToWorker>(type: string, timeoutMs: number): Promise<T | null> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.#waiters.delete(type);
        resolve(null);
      }, timeoutMs);
      this.#waiters.set(type, (message) => {
        clearTimeout(timer);
        resolve(message as T);
      });
    });
  }

  onMessage(handler: (message: ControllerToWorker) => void) {
    this.#handlers.push(handler);
  }

  onClose(handler: (reason: string) => void) {
    this.#closed.push(handler);
  }
}

export async function runWorker(io: WorkerIO): Promise<Exit> {
  const iterator = (async function* () {
    yield* io.messages;
  })();
  const mailbox = new Mailbox();
  let bytesIn = 0, bytesOut = 0;
  const finish = (state: Exit['state'], reason: string): Exit => {
    const exit: Exit = { t: 'exit', state, reason, bytesIn, bytesOut };
    io.send(exit);
    return exit;
  };

  let init: WorkerInit;
  try {
    const first = await Promise.race([
      iterator.next(),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 10000)),
    ]);
    if (!first || first.done) return finish('failed', 'no_assignment');
    init = validateInit(first.value);
  } catch (error) {
    if (error instanceof WorkerExit) return finish(error.state, error.reason);
    return finish('refused', 'invalid_assignment');
  }
  io.send({ t: 'started' });
  // Pump the remaining controller messages.
  const pump = (async () => {
    try {
      for (;;) {
        const next = await iterator.next();
        if (next.done) break;
        mailbox.dispatch(next.value as ControllerToWorker);
      }
    } catch { /* controller pipe closed */ }
    mailbox.dispatch({ t: 'close', reason: 'controller_gone' });
  })();

  const rules = loadRules(init.shellDialect);
  const redactor = new Redactor(rules.redact);
  const control = (m: ControlMessage) => io.send({ t: 'control', m });

  const requestCredential = async (): Promise<WorkerCredential | null> => {
    io.send({ t: 'need_credential' });
    const reply = await mailbox.wait<WorkerCredential>('credential', 45000);
    if (!reply || reply.t !== 'credential') return null;
    redactor.addSecret(reply.password);
    redactor.addSecret(reply.passphrase);
    redactor.addSecret(reply.privateKey);
    return reply;
  };

  const verifyKey = async (
    kind: 'ssh' | 'tls',
    algorithm: string,
    fingerprint: string,
    pinned: string | null,
  ) => {
    control({ type: 'state', state: 'hostkey_check' });
    if (pinned) {
      const result = pinned === fingerprint ? 'match' : 'mismatch';
      io.send({ t: 'hostkey', kind, algorithm, fingerprint, result });
      control({ type: 'hostkey', kind, result, algorithm, fingerprint });
      return result === 'match';
    }
    io.send({ t: 'hostkey', kind, algorithm, fingerprint, result: 'unpinned' });
    const decision = await mailbox.wait<{ t: 'hostkey_decision'; accept: boolean }>(
      'hostkey_decision',
      60000,
    );
    const accept = decision?.accept === true;
    control({
      type: 'hostkey',
      kind,
      result: accept ? 'pinned' : 'rejected',
      algorithm,
      fingerprint,
    });
    return accept;
  };

  {
    let exit: Exit;
    if (init.protocol === 'routeros_api') {
      exit = await routerOsTest(init, { verifyKey, requestCredential, io, finish });
    } else {
      exit = await sshSession(init, {
        verifyKey,
        requestCredential,
        io,
        mailbox,
        redactor,
        rules,
        control,
        finish,
        counters: {
          in: (n) => (bytesIn += n),
          out: (n) => (bytesOut += n),
        },
      });
    }
    void pump;
    return exit;
  }
}

interface Helpers {
  verifyKey(
    kind: 'ssh' | 'tls',
    algorithm: string,
    fingerprint: string,
    pinned: string | null,
  ): Promise<boolean>;
  requestCredential(): Promise<WorkerCredential | null>;
  io: WorkerIO;
  finish(state: Exit['state'], reason: string): Exit;
}

async function routerOsTest(init: WorkerInit, h: Helpers): Promise<Exit> {
  h.io.send({ t: 'control', m: { type: 'state', state: 'connecting' } });
  let api: RouterOsApi | null = null;
  try {
    const connection = await connectApiSsl(
      init.target.address,
      init.target.port,
      init.limits.connectTimeoutSeconds * 1000,
    );
    api = new RouterOsApi(connection.transport);
    if (!(await h.verifyKey('tls', 'x509', connection.pin, init.tls.pinned))) {
      api.close();
      return h.finish('refused', init.tls.pinned ? 'hostkey_mismatch' : 'hostkey_rejected');
    }
    h.io.send({ t: 'control', m: { type: 'state', state: 'authenticating' } });
    const credential = await h.requestCredential();
    if (!credential?.password) {
      api.close();
      return h.finish('failed', 'credential_unavailable');
    }
    try {
      await api.login(credential.username || init.username, credential.password);
    } catch (error) {
      if (error instanceof RouterOsApiError && error.code === 'auth_failed') {
        h.io.send({ t: 'credential_result', result: 'auth_failed' });
        api.close();
        return h.finish('failed', 'auth_failed');
      }
      throw error;
    } finally {
      credential.password = '';
    }
    h.io.send({ t: 'credential_result', result: 'used' });
    const facts = await api.facts();
    h.io.send({ t: 'facts', facts });
    api.close();
    return h.finish('closed', 'test_ok');
  } catch (error) {
    api?.close();
    const code = error instanceof RouterOsApiError ? error.code : 'connect_failed';
    return h.finish(
      'failed',
      ['tls_failed', 'connect_failed', 'timeout'].includes(code)
        ? (code === 'timeout' ? 'connect_failed' : code)
        : 'protocol_error',
    );
  }
}

interface SshHelpers extends Helpers {
  mailbox: Mailbox;
  redactor: Redactor;
  rules: ReturnType<typeof loadRules>;
  control(m: ControlMessage): void;
  counters: { in(n: number): void; out(n: number): void };
}

function sshSession(init: WorkerInit, h: SshHelpers): Promise<Exit> {
  return new Promise<Exit>((resolve) => {
    const client = new Client();
    // deno-lint-ignore no-explicit-any
    let stream: any = null;
    let done = false;
    let credential: WorkerCredential | null = null;
    let attempts: Record<string, unknown>[] | null = null;
    let authenticated = false;
    let lastActivity = Date.now();
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    let idleTimer: ReturnType<typeof setInterval> | null = null;
    let lastThrottleNotice = 0;
    const sanitizer = new TerminalSanitizer();
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
    const emitCast = (line: string) => cast && h.io.send({ t: 'cast', line });
    const classifier = new Classifier(h.rules);
    const gate = new InputGate(classifier, init.level, {
      toDevice: (data) => {
        if (!stream) return;
        h.counters.out(new TextEncoder().encode(data).length);
        stream.write(data);
      },
      control: h.control,
      event: (e) => h.io.send({ t: 'event', e }),
      marker: (label) => cast && emitCast(cast.marker(label)),
      redactLine: (line) => h.redactor.redactText(line),
    }, init.limits.verdictTimeoutSeconds);

    const emitOutput = (text: string) => {
      if (!text) return;
      h.io.send({ t: 'output', d: text });
      if (cast) emitCast(cast.output(text));
    };

    const end = (state: Exit['state'], reason: string) => {
      if (done) return;
      done = true;
      if (flushTimer) clearTimeout(flushTimer);
      if (idleTimer) clearInterval(idleTimer);
      gate.close();
      emitOutput(h.redactor.flush(true) + h.redactor.end());
      credential = null;
      attempts = null;
      try {
        client.end();
      } catch { /* closed */ }
      h.control({ type: 'state', state: state === 'closed' ? 'closed' : 'failed', reason });
      resolve(h.finish(state, reason));
    };

    h.mailbox.onClose((reason) =>
      end('closed', reason === 'controller_gone' ? 'gateway_closed' : reason)
    );
    h.mailbox.onMessage((message) => {
      if (!stream || done) return;
      if (message.t === 'input') {
        lastActivity = Date.now();
        gate.input(message.d);
      } else if (message.t === 'resize') {
        stream.setWindow(message.rows, message.cols, 0, 0);
        if (cast) emitCast(cast.resize(message.cols, message.rows));
      } else if (message.t === 'confirm') {
        gate.decide(message.m);
      }
    });

    const onData = (chunk: Uint8Array) => {
      lastActivity = Date.now();
      h.counters.in(chunk.length);
      const { pauseMs, exceeded } = limiter.take(chunk.length);
      if (exceeded) {
        end('closed', 'output_limit');
        return;
      }
      if (pauseMs > 0 && stream) {
        stream.pause();
        setTimeout(() => !done && stream?.resume(), Math.min(pauseMs, 2000));
        if (Date.now() - lastThrottleNotice > 10000) {
          lastThrottleNotice = Date.now();
          h.control({
            type: 'notice',
            code: 'output_throttled',
            message: 'Device output is being throttled.',
          });
        }
      }
      const text = sanitizer.push(decoder.decode(chunk, { stream: true }));
      gate.observeOutput(text);
      emitOutput(h.redactor.push(text));
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = setTimeout(() => emitOutput(h.redactor.flush()), FLUSH_MS);
    };
    const decoder = new TextDecoder();

    client.on('ready', () => {
      authenticated = true;
      credential = null;
      attempts = null;
      h.io.send({ t: 'credential_result', result: 'used' });
      if (init.mode === 'test') {
        h.io.send({ t: 'facts', facts: {} });
        end('closed', 'test_ok');
        return;
      }
      client.shell(
        { term: 'xterm-256color', cols: init.terminal.cols, rows: init.terminal.rows },
        // deno-lint-ignore no-explicit-any
        (error: Error | undefined, s: any) => {
          if (error) {
            end('failed', 'shell_refused');
            return;
          }
          stream = s;
          if (cast) emitCast(cast.headerLine());
          h.io.send({ t: 'ready' });
          h.control({ type: 'state', state: 'ready' });
          s.on('data', onData);
          s.stderr?.on('data', onData);
          s.on('close', () => end('closed', 'device_closed'));
          idleTimer = setInterval(() => {
            if (Date.now() - lastActivity > init.limits.idleSeconds * 1000) {
              end('closed', 'idle_timeout');
            }
          }, 5000);
        },
      );
    });
    client.on('error', (error: Error & { level?: string }) => {
      if (done) return;
      if (
        /authentication methods failed/i.test(error.message) ||
        error.level === 'client-authentication'
      ) {
        h.io.send({ t: 'credential_result', result: 'auth_failed' });
        end('failed', 'auth_failed');
      } else if (/host key|hostkey|verification/i.test(error.message) || hostKeyRefused) {
        end('refused', hostKeyReason);
      } else {
        end('failed', authenticated ? 'device_error' : 'connect_failed');
      }
    });
    client.on('close', () => end('closed', authenticated ? 'device_closed' : 'connect_failed'));

    let hostKeyRefused = false;
    let hostKeyReason = 'hostkey_mismatch';
    h.control({ type: 'state', state: 'connecting' });
    client.connect({
      host: init.target.address,
      port: init.target.port,
      username: init.username,
      ident: 'MNSCloud-AccessGateway',
      readyTimeout: init.limits.connectTimeoutSeconds * 1000,
      keepaliveInterval: 30000,
      keepaliveCountMax: 3,
      // The host key is verified before any authentication method is tried.
      hostVerifier: (key: Uint8Array, verify: (ok: boolean) => void) => {
        const fingerprint = sshFingerprint(key);
        h.verifyKey('ssh', sshKeyAlgorithm(key), fingerprint, init.hostKey.pinned).then((ok) => {
          if (!ok) {
            hostKeyRefused = true;
            hostKeyReason = init.hostKey.pinned ? 'hostkey_mismatch' : 'hostkey_rejected';
          }
          verify(ok);
          if (!ok) setTimeout(() => end('refused', hostKeyReason), 0);
        });
      },
      // The credential is pulled only now, after the host key was accepted.
      authHandler: (
        _methodsLeft: string[] | null,
        _partial: boolean | null,
        next: (method: Record<string, unknown> | false) => void,
      ) => {
        const advance = () => {
          const method = attempts?.shift();
          next(method ?? false);
        };
        if (attempts) {
          advance();
          return;
        }
        h.control({ type: 'state', state: 'authenticating' });
        h.requestCredential().then((received) => {
          if (!received || (!received.password && !received.privateKey)) {
            next(false);
            setTimeout(() => end('failed', 'credential_unavailable'), 0);
            return;
          }
          credential = received;
          const username = received.username || init.username;
          const list: Record<string, unknown>[] = [];
          if (received.privateKey) {
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
        });
      },
    });
    void credential;
  });
}
