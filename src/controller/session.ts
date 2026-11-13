// One connection on the controller side: network namespace, sandboxed worker, browser socket,
// API calls (host key, credential pull, events, recording parts, finish). The controller never
// interprets device output: the worker sends it already sanitized and redacted.

import {
  controlFrame,
  type ControlMessage,
  outputFrame,
  parseBrowserFrame,
  READY_FRAME,
} from '../shared/framing.ts';
import type { CommandEvent, Facts, WorkerInit, WorkerToController } from '../shared/ipc.ts';
import type { Assignment, FinishBody, HostKeyResponse } from './contract.ts';
import { type Bridge, startBridge } from './bridge.ts';
import { MgmtVpnUnavailable, type SessionNet } from './netns.ts';
import type { Unwrapper } from './openvault.ts';
import { RecordingUploader } from './recording.ts';
import type { SandboxLimits } from './sandbox.ts';
import { OpenError, type OpenSpec, type TunnelStream } from '../shared/tunnel.ts';
import type { WorkerHandle, WorkerLauncher } from './worker_launcher.ts';

export interface RuntimeEvent {
  seq: number;
  at: string;
  type: 'state' | 'hostkey' | 'command' | 'notice' | 'credential';
  [key: string]: unknown;
}

/** API calls a session makes (implemented over the control plane; faked by tests). */
export interface SessionApi {
  hostKey(
    connection: string,
    body: {
      kind: 'ssh' | 'tls';
      algorithm: string;
      fingerprint: string;
      result: 'match' | 'mismatch' | 'unpinned';
    },
  ): Promise<HostKeyResponse>;
  credential(
    connection: string,
  ): Promise<{ credentialUseUUID: string; wrapToken: string; ttlSeconds: number }>;
  credentialResult(
    connection: string,
    body: {
      credentialUseUUID: string;
      result: 'used' | 'auth_failed' | 'unwrap_failed' | 'unused';
    },
  ): Promise<void>;
  events(connection: string, events: RuntimeEvent[]): Promise<void>;
  recordingPart(
    connection: string,
    index: number,
    bytes: Uint8Array,
    sha256: string,
  ): Promise<void>;
  finish(connection: string, body: FinishBody): Promise<void>;
}

export interface SessionNetworkManager {
  create(
    connectionUUID: string,
    target: { address: string; port: number },
    mgmt?: { hubUUID: string; source: string } | null,
  ): Promise<SessionNet>;
  destroy(
    net: SessionNet,
    target: { address: string; port: number },
    mgmt?: { hubUUID: string; source: string } | null,
  ): Promise<void>;
}

export interface BrowserSocket {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
}

/** Tunnels of the tenant connectors attached to this gateway (`ConnectorHub`). */
export interface ConnectorTransport {
  has(connectorUuid: string): boolean;
  open(connectorUuid: string, spec: OpenSpec, fingerprint?: string | null): Promise<TunnelStream>;
}

/**
 * Finish reasons a connector may cause. The connector is outside the platform's trust boundary, so
 * it cannot choose the reason text: anything not listed becomes `connector_open_failed`.
 */
const REFUSED_OPEN = new Set([
  'destination_refused',
  'not_allowed',
  'protocol_refused',
  'api_refused',
  'invalid_address',
  'invalid_port',
  'invalid_open',
  'connector_key_mismatch',
]);
const FAILED_OPEN = new Set([
  'connector_offline',
  'api_unavailable',
  'connect_failed',
  'connect_timeout',
  'open_timeout',
  'too_many_streams',
  'tunnel_closed',
  'tunnel_exhausted',
]);

/** Maps an open failure to the fixed (state, reason) pair reported to the API. */
export function openFailure(code: string): { state: 'refused' | 'failed'; reason: string } {
  if (REFUSED_OPEN.has(code)) return { state: 'refused', reason: code };
  if (FAILED_OPEN.has(code)) return { state: 'failed', reason: code };
  return { state: 'failed', reason: 'connector_open_failed' };
}

export interface SessionDeps {
  api: SessionApi;
  /** Connector transport (null when the node does not serve connectors). */
  connectors?: ConnectorTransport | null;
  /** Directory of the worker bridge sockets (tests use a temporary one). */
  bridgeDir?: string;
  unwrap: Unwrapper;
  launcher: WorkerLauncher;
  networks: SessionNetworkManager | null;
  sandbox: Omit<SandboxLimits, 'maxSessionSeconds'>;
  log(message: string): void;
}

const CLOSE_REASONS: Record<string, [number, string]> = {
  hostkey_mismatch: [4409, 'The device host key changed.'],
  hostkey_rejected: [4403, 'The device host key was not accepted.'],
  auth_failed: [4401, 'The device refused the credential.'],
  credential_unavailable: [4401, 'The credential is not available.'],
  output_limit: [4413, 'Device output limit reached.'],
  idle_timeout: [4408, 'Idle timeout.'],
  max_duration: [4408, 'Maximum session duration reached.'],
};

export class Session {
  readonly startedAt = Date.now();
  #worker: WorkerHandle | null = null;
  #net: SessionNet | null = null;
  #bridge: Bridge | null = null;
  #browser: BrowserSocket | null = null;
  #browserQueue: string[] = [];
  #events: RuntimeEvent[] = [];
  #seq = 0;
  #eventTimer: ReturnType<typeof setInterval> | null = null;
  #eventChain: Promise<void> = Promise.resolve();
  #recording: RecordingUploader | null = null;
  #facts: Facts | null = null;
  #credentialUse: string | null = null;
  #exit: Extract<WorkerToController, { t: 'exit' }> | null = null;
  #finished = false;
  #closeReason: string | null = null;
  #maxTimer: ReturnType<typeof setTimeout> | null = null;
  #resolveDone!: () => void;
  readonly done = new Promise<void>((resolve) => (this.#resolveDone = resolve));

  constructor(readonly assignment: Assignment, private readonly deps: SessionDeps) {}

  get uuid() {
    return this.assignment.connectionUUID;
  }

  /** The worker handle (tests and drain). */
  get worker() {
    return this.#worker;
  }

  /** Console mode: the browser presented the ticket of this assignment. */
  attachBrowser(socket: BrowserSocket) {
    this.#browser = socket;
    const previous = socket.onopen;
    socket.onopen = (event) => {
      previous?.(event);
      this.#flushBrowser();
    };
    socket.onmessage = (event) => {
      if (typeof event.data !== 'string') return;
      const frame = parseBrowserFrame(event.data);
      if (!frame || !this.#worker) return;
      if (frame.kind === 'input') this.#worker.send({ t: 'input', d: frame.data });
      else if (frame.kind === 'resize') {
        this.#worker.send({ t: 'resize', cols: frame.cols, rows: frame.rows });
      } else if (frame.kind === 'confirm') this.#worker.send({ t: 'confirm', m: frame.message });
    };
    socket.onclose = () => this.close('browser_closed');
    socket.onerror = () => this.close('browser_closed');
    void this.#run();
  }

  /** Test mode ("Testar acesso"): no browser. */
  start() {
    void this.#run();
  }

  #toBrowser(frame: string) {
    if (!this.#browser || this.#browser.readyState > 1) return;
    this.#browserQueue.push(frame);
    this.#flushBrowser();
  }

  #flushBrowser() {
    if (!this.#browser || this.#browser.readyState !== 1) return;
    for (const frame of this.#browserQueue.splice(0)) this.#browser.send(frame);
  }

  #control(message: ControlMessage) {
    this.#toBrowser(controlFrame(message));
  }

  #event(type: RuntimeEvent['type'], fields: Record<string, unknown>) {
    this.#events.push({ seq: ++this.#seq, at: new Date().toISOString(), type, ...fields });
    if (this.#events.length >= 50) this.#flushEvents();
  }

  #flushEvents() {
    if (!this.#events.length) return this.#eventChain;
    const batch = this.#events.splice(0);
    this.#eventChain = this.#eventChain.then(() =>
      this.deps.api.events(this.uuid, batch).catch((error) =>
        this.deps.log(`events of ${this.uuid} not delivered: ${(error as Error).message}`)
      )
    );
    return this.#eventChain;
  }

  /** Ends the connection (browser closed, API cancel, gateway shutdown, duration limit). */
  close(reason: string) {
    this.#closeReason ??= reason;
    // Before the worker exists the reason is applied as soon as it starts (see #run).
    this.#worker?.send({ t: 'close', reason });
    // A worker that does not exit in time is killed; the sandbox unit leaves nothing behind.
    setTimeout(() => {
      if (!this.#finished) void this.#worker?.kill();
    }, 5000);
  }

  /** Opens the tunnel stream of a connector connection; finishes the connection and returns null on failure. */
  async #openConnectorStream(): Promise<TunnelStream | null> {
    const a = this.assignment;
    try {
      if (!this.deps.connectors) throw new OpenError('connector_offline');
      return await this.deps.connectors.open(a.connectorUuid!, {
        connectionUuid: a.connectionUUID,
        host: a.target.address,
        port: a.target.port,
      }, a.connectorKeyFingerprint);
    } catch (error) {
      const failure = openFailure(error instanceof OpenError ? error.code : 'connector_failed');
      await this.#finish({
        t: 'exit',
        state: failure.state,
        reason: failure.reason,
        bytesIn: 0,
        bytesOut: 0,
      });
      return null;
    }
  }

  /** Session network or connector bridge; false when the connection was already finished. */
  async #prepareTransport(): Promise<boolean> {
    const a = this.assignment;
    if (a.transport !== 'connector') {
      if (this.deps.networks) {
        try {
          this.#net = await this.deps.networks.create(a.connectionUUID, a.target, a.mgmtVpn);
        } catch (error) {
          if (!(error instanceof MgmtVpnUnavailable)) throw error;
          this.deps.log(`connection ${this.uuid}: ${error.reason}`);
          await this.#finish({
            t: 'exit',
            state: 'failed',
            reason: error.reason,
            bytesIn: 0,
            bytesOut: 0,
          });
          return false;
        }
      } else if (a.transport === 'mgmt_vpn') {
        await this.#finish({
          t: 'exit',
          state: 'failed',
          reason: 'mgmt_vpn_unavailable',
          bytesIn: 0,
          bytesOut: 0,
        });
        return false;
      }
      return true;
    }
    const stream = await this.#openConnectorStream();
    if (!stream) return false;
    try {
      this.#bridge = await startBridge(stream, this.deps.bridgeDir);
    } catch (error) {
      stream.close();
      throw error;
    }
    return true;
  }

  async #run() {
    const a = this.assignment;
    this.#event('state', { state: 'starting' });
    this.#eventTimer = setInterval(() => this.#flushEvents(), 1000);
    this.#control({ type: 'state', state: 'connecting' });
    try {
      if (!(await this.#prepareTransport())) return;
      this.#worker = await this.deps.launcher.launch(
        a.target,
        this.#net,
        { ...this.deps.sandbox, maxSessionSeconds: a.limits.maxSessionSeconds },
        this.#bridge ? { connectionUUID: a.connectionUUID, path: this.#bridge.path } : null,
      );
    } catch (error) {
      this.deps.log(`connection ${this.uuid}: sandbox failed: ${(error as Error).message}`);
      await this.#finish({
        t: 'exit',
        state: 'failed',
        reason: 'sandbox_failed',
        bytesIn: 0,
        bytesOut: 0,
      });
      return;
    }
    if (this.#closeReason) this.#worker.send({ t: 'close', reason: this.#closeReason });
    if (a.mode === 'console' && a.recording.enabled) {
      this.#recording = new RecordingUploader(
        (index, bytes, sha256) => this.deps.api.recordingPart(this.uuid, index, bytes, sha256),
        a.recording.partBytes,
        a.recording.partSeconds,
      );
    }
    this.#maxTimer = setTimeout(
      () => this.close('max_duration'),
      a.limits.maxSessionSeconds * 1000,
    );
    const init: WorkerInit = {
      t: 'init',
      connectionUUID: a.connectionUUID,
      mode: a.mode,
      protocol: a.protocol,
      target: a.target,
      ...(this.#bridge
        ? {
          transport: 'connector' as const,
          bridge: this.#worker.bridgePath ?? this.#bridge.path,
          bridgeSecret: this.#bridge.secret,
        }
        : {}),
      shellDialect: a.shellDialect,
      username: a.username,
      level: a.level,
      hostKey: a.hostKey,
      tls: a.tls,
      terminal: a.terminal,
      limits: {
        connectTimeoutSeconds: 15,
        idleSeconds: a.limits.idleSeconds,
        maxOutputBytesPerSecond: a.limits.maxOutputBytesPerSecond,
        maxOutputBytes: a.limits.maxOutputBytes,
        verdictTimeoutSeconds: 120,
      },
      recording: this.#recording !== null,
    };
    this.#worker.send(init);
    const worker = this.#worker;
    try {
      for await (const raw of worker.messages) {
        const message = raw as WorkerToController;
        if (message.t === 'exit') {
          this.#exit = message;
          break;
        }
        await this.#onWorker(message);
      }
    } catch (error) {
      this.deps.log(`connection ${this.uuid}: worker stream failed: ${(error as Error).message}`);
    }
    await worker.exited.catch(() => -1);
    await this.#finish(
      this.#exit ??
        {
          t: 'exit',
          state: 'failed',
          reason: this.#closeReason ?? 'worker_failed',
          bytesIn: 0,
          bytesOut: 0,
        },
    );
  }

  async #onWorker(message: WorkerToController) {
    const worker = this.#worker!;
    switch (message.t) {
      case 'output':
        this.#toBrowser(outputFrame(message.d));
        break;
      case 'control':
        this.#control(message.m);
        if (message.m.type === 'state' || message.m.type === 'notice') {
          this.#event(message.m.type, { ...message.m });
        }
        break;
      case 'ready':
        this.#toBrowser(READY_FRAME);
        break;
      case 'cast':
        this.#recording?.add(message.line);
        break;
      case 'event':
        this.#event('command', { ...(message.e as CommandEvent) });
        break;
      case 'facts':
        this.#facts = message.facts;
        break;
      case 'hostkey': {
        let decision: HostKeyResponse = { decision: 'block', pinned: false };
        try {
          decision = await this.deps.api.hostKey(this.uuid, {
            kind: message.kind,
            algorithm: message.algorithm,
            fingerprint: message.fingerprint,
            result: message.result,
          });
        } catch (error) {
          this.deps.log(
            `connection ${this.uuid}: host key report failed: ${(error as Error).message}`,
          );
        }
        this.#event('hostkey', {
          kind: message.kind,
          fingerprint: message.fingerprint,
          result: message.result,
          decision: decision.decision,
        });
        // A pinned key decides locally (match/mismatch); an unpinned one needs the API to pin it.
        if (message.result === 'unpinned') {
          worker.send({
            t: 'hostkey_decision',
            accept: decision.decision === 'accept' && decision.pinned,
          });
        }
        break;
      }
      case 'need_credential': {
        let use: string | null = null;
        try {
          const grant = await this.deps.api.credential(this.uuid);
          use = grant.credentialUseUUID;
          this.#credentialUse = use;
          const secret = await this.deps.unwrap(grant.wrapToken);
          worker.send({ t: 'credential', ...secret });
          this.#event('credential', { result: 'delivered' });
        } catch (error) {
          this.deps.log(
            `connection ${this.uuid}: credential unavailable: ${(error as Error).message}`,
          );
          worker.send({ t: 'credential_unavailable' });
          this.#event('credential', { result: 'unavailable' });
          if (use) {
            await this.deps.api.credentialResult(this.uuid, {
              credentialUseUUID: use,
              result: 'unwrap_failed',
            }).catch(() => {});
            this.#credentialUse = null;
          }
        }
        break;
      }
      case 'credential_result':
        if (this.#credentialUse) {
          const use = this.#credentialUse;
          this.#credentialUse = null;
          await this.deps.api.credentialResult(this.uuid, {
            credentialUseUUID: use,
            result: message.result,
          }).catch(
            (error) =>
              this.deps.log(
                `connection ${this.uuid}: credential result not delivered: ${
                  (error as Error).message
                }`,
              ),
          );
        }
        break;
      case 'started':
        break;
    }
  }

  async #finish(exit: Extract<WorkerToController, { t: 'exit' }>) {
    if (this.#finished) return;
    this.#finished = true;
    if (this.#maxTimer) clearTimeout(this.#maxTimer);
    if (this.#eventTimer) clearInterval(this.#eventTimer);
    const reason = this.#closeReason && exit.reason === 'gateway_closed'
      ? this.#closeReason
      : exit.reason;
    if (this.#credentialUse) {
      await this.deps.api.credentialResult(this.uuid, {
        credentialUseUUID: this.#credentialUse,
        result: 'unused',
      }).catch(() => {});
    }
    this.#event('state', { state: exit.state, reason });
    const recording = (await this.#recording?.finish()) ?? null;
    await this.#flushEvents();
    if (this.#browser && this.#browser.readyState <= 1) {
      this.#control({
        type: 'state',
        state: exit.state === 'closed' ? 'closed' : 'failed',
        reason,
      });
      this.#flushBrowser();
      const [code, text] = CLOSE_REASONS[reason] ??
        [exit.state === 'closed' ? 1000 : 4500, 'Console closed.'];
      try {
        this.#browser.close(code, text);
      } catch { /* closed */ }
    }
    this.#bridge?.close();
    if (this.#net && this.deps.networks) {
      await this.deps.networks.destroy(this.#net, this.assignment.target, this.assignment.mgmtVpn)
        .catch(() => {});
    }
    const body: FinishBody = {
      state: exit.state,
      reason,
      bytesFromDevice: exit.bytesIn,
      bytesToDevice: exit.bytesOut,
      durationMs: Date.now() - this.startedAt,
      recording: recording
        ? { parts: recording.parts, bytes: recording.bytes, sha256: recording.sha256 }
        : null,
      facts: this.#facts
        ? Object.fromEntries(
          Object.entries(this.#facts).filter(([, v]) => typeof v === 'string'),
        ) as Record<string, string>
        : null,
    };
    await this.deps.api.finish(this.uuid, body).catch((error) =>
      this.deps.log(`connection ${this.uuid}: finish not delivered: ${(error as Error).message}`)
    );
    this.#resolveDone();
  }
}
