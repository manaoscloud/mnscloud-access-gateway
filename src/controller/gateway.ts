// Gateway core: takes assignments from the API, keeps console tickets, starts sessions and
// terminates browser WebSockets (only from the edge hosts, only with a valid ticket).

import { checkConnectorDestination } from '../shared/destination.ts';
import { cidrContains, parseAddress, parseCidr } from '../shared/ip.ts';
import {
  type Assignment,
  type AttachTicket,
  ContractError,
  type FinishBody,
  parseAssignment,
} from './contract.ts';
import type { ConnectorHub } from './connector_hub.ts';
import { checkDestination, type Denylist } from './denylist.ts';
import { MAX_OBSERVERS, Session, type SessionDeps } from './session.ts';
import { TicketBook, ticketHash } from './ticket.ts';

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
  /**
   * How long a browser with a ticket this gateway does not know yet waits for its assignment
   * (the API hands the ticket out before the next assignments poll delivers it). Default 5 s.
   */
  ticketArrivalMs?: number;
}

const TICKET_ARRIVAL_MS = 5000;
const TICKET_RETRY_MS = 100;

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
  /** Attach tickets of live support connections of this gateway (reattach, observers). */
  readonly attachTickets = new TicketBook<Pick<AttachTicket, 'connectionUUID' | 'role'>>();
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

  /** Destination, protocol and (connector) tunnel checks; null when the assignment may proceed. */
  #preflight(assignment: Assignment): { reason: string; state: FinishBody['state'] } | null {
    const { address, port } = assignment.target;
    if (assignment.transport === 'mgmt_vpn') {
      // The hub range is private on purpose: the denylist does not apply here, `MgmtVpn.require`
      // checks the range at session creation and the host firewall lets only this path use it.
      return [23, 8728].includes(port) ? { reason: 'protocol_refused', state: 'refused' } : null;
    }
    if (assignment.transport !== 'connector') {
      const destination = checkDestination(address, this.options.denylist);
      if (destination.allowed && ![23, 8728].includes(port)) return null;
      return {
        reason: destination.allowed ? 'protocol_refused' : 'destination_refused',
        state: 'refused',
      };
    }
    // Tenant private ranges are the point of a connector: only the always-refused set applies
    // here (the API and the connector check the tenant's allowed networks).
    const verdict = checkConnectorDestination(address, port, { allowedCidrs: [] });
    if (verdict) {
      return {
        reason: verdict === 'protocol_refused' ? verdict : 'destination_refused',
        state: 'refused',
      };
    }
    const tunnelKey = this.options.hub?.fingerprintOf(assignment.connectorUuid!) ?? null;
    if (tunnelKey === null) return { reason: 'connector_offline', state: 'failed' };
    if (tunnelKey !== assignment.connectorKeyFingerprint) {
      return { reason: 'connector_key_mismatch', state: 'refused' };
    }
    return null;
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
    const refused = this.#preflight(assignment);
    if (refused) {
      await this.options.deps.api.finish(
        assignment.connectionUUID,
        refusal(assignment, refused.reason, refused.state),
      ).catch(() => {});
      return 'refused';
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
    this.attachTickets.sweep(now);
    for (const assignment of this.tickets.sweep(now)) {
      this.#pending.delete(assignment.connectionUUID);
      void this.options.deps.api.finish(
        assignment.connectionUUID,
        refusal(assignment, 'ticket_expired', 'expired'),
      ).catch(() => {});
    }
  }

  /**
   * Attach tickets from the API: kept only for a connection that is a live session here
   * (deduplicated by hash; an expired one is dropped silently by the sweep).
   */
  addAttachTickets(list: AttachTicket[]) {
    for (const item of list) {
      // Only detachable consoles of support sessions can be attached to.
      if (
        !this.sessions.get(item.connectionUUID)?.assignment.detachable ||
        this.attachTickets.knows(item.sha256)
      ) continue;
      this.attachTickets.add(item.sha256, Date.parse(item.expiresAt), {
        connectionUUID: item.connectionUUID,
        role: item.role,
      });
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

  /**
   * Consumes the ticket from the assignment book or the attach book; one neither book knows yet
   * (only `unknown`: never a used, expired or malformed one) is retried until its assignment
   * arrives or the wait ends.
   */
  async #awaitTicket(ticket: string | null): Promise<
    | { ok: true; kind: 'assignment'; value: Assignment }
    | { ok: true; kind: 'attach'; value: Pick<AttachTicket, 'connectionUUID' | 'role'> }
    | { ok: false }
  > {
    const deadline = Date.now() + (this.options.ticketArrivalMs ?? TICKET_ARRIVAL_MS);
    for (;;) {
      const result = await this.tickets.consume(ticket);
      if (result.ok) return { ok: true, kind: 'assignment', value: result.value };
      const attach = await this.attachTickets.consume(ticket);
      if (attach.ok) return { ok: true, kind: 'attach', value: attach.value };
      const unknown = result.reason === 'unknown' && attach.reason === 'unknown';
      if (!unknown || Date.now() >= deadline || this.#draining) return { ok: false };
      await new Promise((resolve) => setTimeout(resolve, TICKET_RETRY_MS));
    }
  }

  /** Attach ticket: the API consumes it for the connection and names the role (or refuses). */
  async #attach(
    request: Request,
    ticket: string,
    value: Pick<AttachTicket, 'connectionUUID' | 'role'>,
  ): Promise<Response> {
    const refused = () =>
      new Response('Console ticket is invalid or expired.', {
        status: 401,
        headers: { 'Cache-Control': 'no-store' },
      });
    const session = this.sessions.get(value.connectionUUID);
    if (!session?.assignment.detachable) return refused();
    if (value.role === 'observer' && session.observerCount >= MAX_OBSERVERS) return refused();
    let role: AttachTicket['role'];
    try {
      role = (await this.options.deps.api.attach(value.connectionUUID, await ticketHash(ticket)))
        .role;
      if (role !== value.role) throw new Error('role mismatch');
    } catch (error) {
      this.options.deps.log(
        `attach to ${value.connectionUUID} refused: ${(error as Error).message}`,
      );
      return refused();
    }
    const { socket, response } = Deno.upgradeWebSocket(request, { idleTimeout: 60 });
    session.attachClient(socket, role);
    return response;
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
    const result = await this.#awaitTicket(url.searchParams.get('ticket'));
    if (!result.ok) {
      return new Response('Console ticket is invalid or expired.', {
        status: 401,
        headers: { 'Cache-Control': 'no-store' },
      });
    }
    if (result.kind === 'attach') {
      return this.#attach(request, url.searchParams.get('ticket')!, result.value);
    }
    this.#pending.delete(result.value.connectionUUID);
    const { socket, response } = Deno.upgradeWebSocket(request, { idleTimeout: 60 });
    this.#startSession(result.value).attachBrowser(socket);
    return response;
  }
}
