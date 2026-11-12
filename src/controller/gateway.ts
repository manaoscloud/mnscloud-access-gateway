// Gateway core: takes assignments from the API, keeps console tickets, starts sessions and
// terminates browser WebSockets (only from the edge hosts, only with a valid ticket).

import { checkConnectorDestination } from '../shared/destination.ts';
import { cidrContains, parseAddress, parseCidr } from '../shared/ip.ts';
import { type Assignment, ContractError, type FinishBody, parseAssignment } from './contract.ts';
import type { ConnectorHub } from './connector_hub.ts';
import { checkDestination, type Denylist } from './denylist.ts';
import { Session, type SessionDeps } from './session.ts';
import { TicketBook } from './ticket.ts';

export interface GatewayOptions {
  gatewayKey: string;
  /** The listener's own address (local validation probe). */
  listenAddress?: string;
  edgeSources: string[];
  denylist: Denylist;
  capacity: number;
  version: string;
  deps: SessionDeps;
  /** Connector tunnels (`/access-gateway/<key>/connector`); absent when not served. */
  hub?: ConnectorHub;
}

function refusal(
  _assignment: { connectionUUID: string },
  reason: string,
  state: FinishBody['state'] = 'refused',
): FinishBody {
  return {
    state,
    reason,
    bytesFromDevice: 0,
    bytesToDevice: 0,
    durationMs: 0,
    recording: null,
    facts: null,
  };
}

export class Gateway {
  readonly sessions = new Map<string, Session>();
  readonly tickets = new TicketBook<Assignment>();
  #pending = new Set<string>();
  #draining = false;
  #sweeper: ReturnType<typeof setInterval>;

  constructor(private options: GatewayOptions) {
    this.#sweeper = setInterval(() => this.sweep(), 5000);
  }

  update(options: Partial<Pick<GatewayOptions, 'edgeSources' | 'denylist' | 'capacity'>>) {
    this.options = { ...this.options, ...options };
  }

  get freeSlots() {
    return Math.max(0, this.options.capacity - this.sessions.size - this.#pending.size);
  }

  get activeSessions() {
    return this.sessions.size;
  }

  /** Accepts one raw assignment from the API; refused ones are finished at once. */
  async accept(raw: unknown): Promise<'started' | 'waiting' | 'refused'> {
    const uuid = typeof (raw as { connectionUUID?: unknown })?.connectionUUID === 'string'
      ? (raw as { connectionUUID: string }).connectionUUID
      : null;
    let assignment: Assignment;
    try {
      assignment = parseAssignment(raw);
    } catch (error) {
      if (uuid && /^[0-9a-f-]{36}$/.test(uuid)) {
        const reason = error instanceof ContractError && /^[a-z_]+$/.test(error.message)
          ? error.message
          : 'invalid_assignment';
        await this.options.deps.api.finish(uuid, refusal({ connectionUUID: uuid }, reason)).catch(
          () => {},
        );
      }
      return 'refused';
    }
    if (
      this.sessions.has(assignment.connectionUUID) || this.#pending.has(assignment.connectionUUID)
    ) return 'waiting';
    if (assignment.transport === 'connector') {
      // Tenant private ranges are the point of a connector: only the always-refused set applies
      // here (the API and the connector check the tenant's allowed networks).
      const verdict = checkConnectorDestination(
        assignment.target.address,
        assignment.target.port,
        { allowedCidrs: [] },
      );
      if (verdict) {
        await this.options.deps.api.finish(
          assignment.connectionUUID,
          refusal(assignment, verdict === 'protocol_refused' ? verdict : 'destination_refused'),
        ).catch(() => {});
        return 'refused';
      }
      const tunnelKey = this.options.hub?.fingerprintOf(assignment.connectorUuid!) ?? null;
      if (tunnelKey !== null && tunnelKey !== assignment.connectorKeyFingerprint) {
        await this.options.deps.api.finish(
          assignment.connectionUUID,
          refusal(assignment, 'connector_key_mismatch'),
        ).catch(() => {});
        return 'refused';
      }
      if (tunnelKey === null) {
        await this.options.deps.api.finish(
          assignment.connectionUUID,
          refusal(assignment, 'connector_offline', 'failed'),
        ).catch(() => {});
        return 'refused';
      }
    } else {
      const destination = checkDestination(assignment.target.address, this.options.denylist);
      if (!destination.allowed || [23, 8728].includes(assignment.target.port)) {
        await this.options.deps.api.finish(
          assignment.connectionUUID,
          refusal(assignment, destination.allowed ? 'protocol_refused' : 'destination_refused'),
        ).catch(() => {});
        return 'refused';
      }
    }
    if (this.#draining || this.freeSlots <= 0) {
      await this.options.deps.api.finish(
        assignment.connectionUUID,
        refusal(assignment, 'gateway_full', 'failed'),
      ).catch(() => {});
      return 'refused';
    }
    if (assignment.mode === 'test') {
      this.#startSession(assignment).start();
      return 'started';
    }
    this.#pending.add(assignment.connectionUUID);
    this.tickets.add(
      assignment.ticket!.sha256,
      Date.parse(assignment.ticket!.expiresAt),
      assignment,
    );
    return 'waiting';
  }

  #startSession(assignment: Assignment) {
    const session = new Session(assignment, this.options.deps);
    this.sessions.set(assignment.connectionUUID, session);
    session.done.finally(() => this.sessions.delete(assignment.connectionUUID));
    return session;
  }

  /** Expired console tickets: the connection never opened. */
  sweep(now = Date.now()) {
    for (const assignment of this.tickets.sweep(now)) {
      this.#pending.delete(assignment.connectionUUID);
      void this.options.deps.api.finish(
        assignment.connectionUUID,
        refusal(assignment, 'ticket_expired', 'expired'),
      ).catch(() => {});
    }
  }

  cancel(connectionUUID: string) {
    if (this.#pending.delete(connectionUUID)) {
      this.tickets.remove((a) => a.connectionUUID === connectionUUID);
      void this.options.deps.api.finish(
        connectionUUID,
        refusal({ connectionUUID }, 'cancelled', 'closed'),
      ).catch(() => {});
    }
    this.sessions.get(connectionUUID)?.close('cancelled');
  }

  async drain(reason = 'gateway_shutdown', timeoutMs = 10000) {
    this.#draining = true;
    clearInterval(this.#sweeper);
    for (const uuid of [...this.#pending]) this.cancel(uuid);
    for (const session of this.sessions.values()) session.close(reason);
    void this.options.hub?.drain();
    await Promise.race([
      Promise.all([...this.sessions.values()].map((s) => s.done)),
      new Promise((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
  }

  #edgeAllowed(remote: string) {
    const address = parseAddress(remote.replace(/^::ffff:(?=\d+\.)/, ''));
    if (!address) return false;
    if (address.family === 4 && address.text.startsWith('127.')) return true;
    if (address.family === 6 && address.text === '::1') return true;
    if (
      this.options.listenAddress && parseAddress(this.options.listenAddress)?.text === address.text
    ) return true;
    return this.options.edgeSources.some((cidr) => {
      const parsed = parseCidr(cidr);
      return parsed ? cidrContains(parsed, address) : false;
    });
  }

  /** HTTP handler of the 7443 listener. */
  async handle(request: Request, remote: string): Promise<Response> {
    if (!this.#edgeAllowed(remote)) return new Response('Forbidden', { status: 403 });
    const url = new URL(request.url);
    if (url.pathname === '/healthz' && request.method === 'GET') {
      return Response.json({
        status: this.#draining ? 'draining' : 'ok',
        version: this.options.version,
        activeSessions: this.sessions.size,
        freeSlots: this.freeSlots,
      }, { headers: { 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === `/access-gateway/${this.options.gatewayKey}/connector`) {
      if (!this.options.hub) return new Response('Not found', { status: 404 });
      if (this.#draining) return new Response('Draining', { status: 503 });
      return this.options.hub.handleUpgrade(request, remote);
    }
    const paths = [`/access-gateway/${this.options.gatewayKey}/ws`, '/ws'];
    if (!paths.includes(url.pathname)) return new Response('Not found', { status: 404 });
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('WebSocket required', { status: 426 });
    }
    const result = await this.tickets.consume(url.searchParams.get('ticket'));
    if (!result.ok) {
      return new Response('Console ticket is invalid or expired.', {
        status: 401,
        headers: { 'Cache-Control': 'no-store' },
      });
    }
    this.#pending.delete(result.value.connectionUUID);
    const { socket, response } = Deno.upgradeWebSocket(request, { idleTimeout: 60 });
    this.#startSession(result.value).attachBrowser(socket);
    return response;
  }
}
