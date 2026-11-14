// Controller <-> worker messages: one JSON object per line over the worker's stdin/stdout pipes
// (systemd-run --pipe hands the pipe file descriptors straight to the sandboxed process). The
// credential travels only on this pipe and lives only in the worker's memory.

import type { ExecPayload, ExecResult } from './exec.ts';
import type { CommandClass, ConfirmMessage, ControlMessage } from './framing.ts';

/** Bridge socket paths the controller creates (and the only ones a worker may be given). */
export function validBridgePath(path: unknown): path is string {
  return typeof path === 'string' && path.length <= 200 &&
    /^\/[A-Za-z0-9._/-]+\.sock$/.test(path) &&
    !path.includes('..') && !path.includes('//');
}

export type ShellDialect = 'routeros' | 'linux' | 'proxmox' | 'vrp' | 'other';
export type SupportLevel = 'n1' | 'n2' | 'n3';

export interface WorkerInit {
  t: 'init';
  connectionUUID: string;
  mode: 'console' | 'test' | 'exec';
  protocol: 'ssh' | 'routeros_api';
  target: { address: string; port: number };
  /** `connector`: connect to the unix socket `bridge` instead of the network. */
  transport?: 'direct' | 'connector';
  bridge?: string;
  /** 64 hex characters the worker writes first on the bridge socket. */
  bridgeSecret?: string;
  shellDialect: ShellDialect;
  username: string;
  level: SupportLevel;
  hostKey: { pinned: string | null };
  tls: { pinned: string | null };
  terminal: { cols: number; rows: number };
  limits: {
    connectTimeoutSeconds: number;
    idleSeconds: number;
    maxOutputBytesPerSecond: number;
    maxOutputBytes: number;
    verdictTimeoutSeconds: number;
  };
  recording: boolean;
  /** Exec mode (AI copilot): the validated command payload. */
  exec?: ExecPayload;
}

export interface WorkerCredential {
  t: 'credential';
  username?: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

export type ControllerToWorker =
  | WorkerInit
  | WorkerCredential
  | { t: 'credential_unavailable' }
  | { t: 'hostkey_decision'; accept: boolean }
  | { t: 'input'; d: string }
  | { t: 'resize'; cols: number; rows: number }
  | { t: 'confirm'; m: ConfirmMessage }
  | { t: 'close'; reason: string };

export interface CommandEvent {
  type: 'command';
  line: string;
  class: CommandClass;
  unknown: boolean;
  verdict: 'allowed' | 'confirmed' | 'denied' | 'blocked' | 'expired';
  level: SupportLevel;
  rule: string | null;
}

export interface Facts {
  identity?: string;
  version?: string;
  boardName?: string;
  architecture?: string;
  uptime?: string;
  cpuLoad?: string;
  freeMemory?: string;
  totalMemory?: string;
  serverBanner?: string;
}

export type WorkerToController =
  | { t: 'started' }
  | {
    t: 'hostkey';
    kind: 'ssh' | 'tls';
    algorithm: string;
    fingerprint: string;
    result: 'match' | 'mismatch' | 'unpinned';
  }
  | { t: 'need_credential' }
  | { t: 'credential_result'; result: 'used' | 'auth_failed' }
  | { t: 'ready' }
  | { t: 'output'; d: string }
  | { t: 'control'; m: ControlMessage }
  | { t: 'event'; e: CommandEvent }
  | { t: 'cast'; line: string }
  | { t: 'facts'; facts: Facts }
  | { t: 'exec_result'; result: ExecResult }
  | {
    t: 'exit';
    state: 'closed' | 'failed' | 'refused';
    reason: string;
    bytesIn: number;
    bytesOut: number;
  };

export function encodeMessage(message: ControllerToWorker | WorkerToController): string {
  return JSON.stringify(message) + '\n';
}

/** Splits a byte stream into JSON lines; lines above `maxLine` characters are an error. */
export class LineDecoder {
  #buffer = '';
  #decoder = new TextDecoder();
  constructor(private readonly maxLine = 1024 * 1024) {}

  push(chunk: Uint8Array): unknown[] {
    this.#buffer += this.#decoder.decode(chunk, { stream: true });
    const out: unknown[] = [];
    let index: number;
    while ((index = this.#buffer.indexOf('\n')) >= 0) {
      const line = this.#buffer.slice(0, index);
      this.#buffer = this.#buffer.slice(index + 1);
      if (line.trim()) out.push(JSON.parse(line));
    }
    if (this.#buffer.length > this.maxLine) throw new Error('IPC line too long');
    return out;
  }
}

export async function* readMessages(
  stream: ReadableStream<Uint8Array>,
  maxLine?: number,
): AsyncGenerator<unknown> {
  const decoder = new LineDecoder(maxLine);
  for await (const chunk of stream) {
    for (const message of decoder.push(chunk)) yield message;
  }
}
