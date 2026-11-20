import { JunosObserver } from './observe.ts';
import { CAP, JUNOS, Netconf, PinnedClient, RpcError } from './netconf.ts';
import { ProtocolError } from './xml.ts';
import { changeGrammarProblem } from '../exec_policy.ts';
export interface Observation {
  lockHeld: boolean;
  pending: 'none' | 'ours' | 'foreign' | 'unknown';
  baselineRestored: boolean;
}
export interface Hooks {
  /** Must read the actual device, never return cached assumptions. Called with candidate lock held. */
  observe?(
    nc: Netconf,
    phase: 'before' | 'loaded' | 'pending' | 'before-confirm' | 'after-confirm',
    signal: AbortSignal,
  ): Promise<Observation>;
  /** Mandatory actual device-file backup. Return only after file-write success proof; no secret output. */
  backup(
    phase: 'pre' | 'post',
    filename: string,
    signal: AbortSignal,
  ): Promise<void>;
  /** Separate newly authenticated/pinned SSH connection, safe reads only. Original lock stays held. */
  verify(signal: AbortSignal): Promise<boolean>;
}
export interface Options {
  commands: readonly string[];
  backupName: string;
  rollbackSeconds: number;
  signal: AbortSignal;
  hooks: Hooks;
  now?: () => number;
  requestTimeoutMs?: number;
  /** Budget of each hook (default: requestTimeoutMs); still capped by the commit deadline. */
  hookTimeoutMs?: { backup?: number; verify?: number };
}
export interface Result {
  state: 'refused' | 'failed' | 'rollback_pending' | 'confirmed' | 'unknown';
  code: string;
  phase: string;
  candidateTouched: boolean;
  commitSent: boolean;
  confirmationSent: boolean;
  /** True once a read-back proved a pending confirmed commit owned by this session. */
  armObserved: boolean;
  backupPre: string | null;
  backupPost: string | null;
}
/** Hooks are mandatory integration proof, NOT fake default implementations. */
export async function change(
  client: PinnedClient,
  options: Options,
): Promise<Result> {
  const { signal, hooks } = options;
  const now = options.now ?? Date.now;
  const observer = new JunosObserver();
  const observe = hooks.observe ?? observer.observe.bind(observer);
  const requestMs = options.requestTimeoutMs ?? 10000;
  const backupMs = options.hookTimeoutMs?.backup ?? requestMs;
  const verifyMs = options.hookTimeoutMs?.verify ?? requestMs;
  const r: Result = {
    state: 'refused',
    code: 'PRECONDITION',
    phase: 'preflight',
    candidateTouched: false,
    commitSent: false,
    confirmationSent: false,
    armObserved: false,
    backupPre: null,
    backupPost: null,
  };
  if (
    !hooks?.backup || !hooks?.verify ||
    !options.commands.length || options.commands.length > 27 ||
    options.commands.some((c) => changeGrammarProblem('junos', c) !== null) ||
    !/^[a-z0-9-]{1,48}$/.test(options.backupName) ||
    !Number.isInteger(options.rollbackSeconds) ||
    options.rollbackSeconds < 120 || options.rollbackSeconds > 900
  ) return r;
  let nc: Netconf | null = null, locked = false, deadline = Infinity;
  const remaining = (cap = requestMs) => Math.min(cap, deadline - now() - 5000);
  const check = () => {
    if (signal.aborted) throw new ProtocolError('CANCELLED');
    if (remaining() <= 0) throw new ProtocolError('DEADLINE');
  };
  const bounded = async <T>(
    call: (s: AbortSignal) => Promise<T>,
    cap = requestMs,
  ): Promise<T> => {
    check();
    const ctl = new AbortController();
    const abort = () => ctl.abort();
    signal.addEventListener('abort', abort, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stop = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        ctl.abort();
        reject(new ProtocolError('TIMEOUT'));
      }, remaining(cap));
      ctl.signal.addEventListener(
        'abort',
        () => reject(new ProtocolError(signal.aborted ? 'CANCELLED' : 'TIMEOUT')),
        { once: true },
      );
    });
    try {
      const out = await Promise.race([call(ctl.signal), stop]);
      check();
      return out;
    } finally {
      if (timer) clearTimeout(timer);
      signal.removeEventListener('abort', abort);
    }
  };
  const ok = async (body: string) => {
    check();
    await nc!.ok(body, signal, remaining());
    check();
  };
  try {
    check();
    nc = await Netconf.open(client, signal, requestMs);
    for (
      const capability of [
        CAP + 'candidate:1.0',
        CAP + 'confirmed-commit:1.1',
        JUNOS,
      ]
    ) {
      if (!nc.capabilities.has(capability)) {
        throw new ProtocolError('UNSUPPORTED_CAPABILITY');
      }
    }
    if (
      !nc.capabilities.has(CAP + 'validate:1.1') &&
      !nc.capabilities.has(CAP + 'validate:1.0')
    ) throw new ProtocolError('UNSUPPORTED_VALIDATE');
    r.phase = 'lock';
    await ok('<lock><target><candidate/></target></lock>');
    locked = true;
    const before = await bounded((s) => observe(nc!, 'before', s));
    if (!before.lockHeld || before.pending !== 'none') {
      throw new ProtocolError('FOREIGN_OR_UNKNOWN_COMMIT');
    }
    r.phase = 'backup-pre';
    const pre = `/var/tmp/${options.backupName}-pre.conf`;
    await bounded((s) => hooks.backup('pre', pre, s), backupMs);
    r.backupPre = pre;
    r.phase = 'load';
    r.candidateTouched = true;
    check();
    await nc.loadSet(options.commands, signal, remaining());
    check();
    const loaded = await bounded((s) => observe(nc!, 'loaded', s));
    if (!loaded.lockHeld || loaded.pending !== 'none') {
      throw new ProtocolError('LOADED_STATE_UNKNOWN');
    }
    r.phase = 'validate';
    await ok('<validate><source><candidate/></source></validate>');
    r.phase = 'commit-confirmed';
    check();
    deadline = now() + options.rollbackSeconds * 1000;
    r.commitSent = true;
    await ok(
      // nosemgrep: javascript.lang.security.html-in-template-string -- XML wire message, rollbackSeconds is a validated integer 120..900
      `<commit><confirmed/><confirm-timeout>${options.rollbackSeconds}</confirm-timeout></commit>`,
    );
    const pending = await bounded((s) => observe(nc!, 'pending', s));
    if (!pending.lockHeld || pending.pending !== 'ours') {
      throw new ProtocolError('COMMIT_OWNERSHIP_UNKNOWN');
    }
    r.armObserved = true;
    // Running now contains the unconfirmed candidate. Operational show configuration | save is valid here.
    r.phase = 'backup-post';
    const post = `/var/tmp/${options.backupName}-post.conf`;
    await bounded((s) => hooks.backup('post', post, s), backupMs);
    r.backupPost = post;
    r.phase = 'verify';
    if (!await bounded((s) => hooks.verify(s), verifyMs)) {
      throw new ProtocolError('VERIFY_FAILED');
    }
    r.phase = 'before-confirm';
    const final = await bounded((s) => observe(nc!, 'before-confirm', s));
    if (!final.lockHeld || final.pending !== 'ours') {
      throw new ProtocolError('COMMIT_OWNERSHIP_LOST');
    }
    check();
    r.phase = 'confirm';
    r.confirmationSent = true;
    await ok('<commit/>');
    r.phase = 'after-confirm';
    const confirmed = await bounded((s) => observe(nc!, 'after-confirm', s));
    if (!confirmed.lockHeld || confirmed.pending !== 'none') {
      throw new ProtocolError('CONFIRMATION_UNKNOWN');
    }
    r.state = 'confirmed';
    r.code = 'CONFIRMED';
    return r;
  } catch (error) {
    r.code = error instanceof RpcError
      ? (r.phase === 'lock' ? 'LOCK_REFUSED' : 'RPC_ERROR')
      : error instanceof ProtocolError
      ? error.code
      : 'HOOK_FAILED';
    // No raw error messages, RPC error-info, configuration, command output, or credentials escape.
    r.state = r.confirmationSent
      ? 'unknown'
      : r.commitSent
      ? 'rollback_pending'
      : r.candidateTouched
      ? 'failed'
      : 'refused';
    return r;
  } finally {
    if (nc) {
      // Closing the nonpersistent NETCONF session is the fallback. Never rollback1, kill another
      // session, or blindly commit. A closed session is NOT proof that rollback completed.
      if (locked && nc.usable && r.state === 'confirmed') {
        const cleanup = new AbortController();
        try {
          await nc.ok(
            '<unlock><target><candidate/></target></unlock>',
            cleanup.signal,
            1000,
          );
        } catch { /* confirmation observed; cleanup uncertainty only */ }
      }
      nc.close();
    }
  }
}

/** Integration entrypoint: cannot accept a caller-supplied observation stub. */
export function observedChange(
  client: PinnedClient,
  options: Omit<Options, 'hooks'> & { hooks: Pick<Hooks, 'backup' | 'verify'> },
): Promise<Result> {
  return change(client, {
    ...options,
    hooks: { backup: options.hooks.backup, verify: options.hooks.verify },
  });
}
