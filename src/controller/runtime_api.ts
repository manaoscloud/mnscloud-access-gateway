// SessionApi and controller calls over the Agent-authenticated control plane.

import type {
  AssignmentsResponse,
  CredentialResponse,
  FinishBody,
  HostKeyResponse,
} from './contract.ts';
import type { ExecResult } from '../shared/exec.ts';
import {
  AttachRefused,
  type ConnectorAttachment,
  type ConnectorRuntimeApi,
} from './connector_hub.ts';
import { type ControlPlane, ControlPlaneRejected } from './control_plane.ts';
import type { BrowserRole, RuntimeEvent, SessionApi } from './session.ts';

export class RuntimeApi implements SessionApi, ConnectorRuntimeApi {
  constructor(private readonly cp: ControlPlane) {}

  config() {
    return this.cp.call<unknown>('GET', '/config');
  }

  assignments(cursor: string, waitSeconds: number, free: number) {
    return this.cp.call<AssignmentsResponse>('GET', '/assignments', undefined, {
      query: { cursor, wait: waitSeconds, free },
      timeoutMs: (waitSeconds + 15) * 1000,
    });
  }

  /** Public key of an active, operational connector of this environment (null when not usable). */
  async connector(uuid: string) {
    try {
      const data = await this.cp.call<{ publicKey?: unknown; attachment?: unknown } | null>(
        'GET',
        `/connectors/${uuid}`,
      );
      if (typeof data?.publicKey !== 'string') return null;
      // An older API sends no attachment: 'here' keeps the previous behavior (key check only).
      const attachment: ConnectorAttachment =
        data.attachment === 'none' || data.attachment === 'other' ? data.attachment : 'here';
      return { publicKey: data.publicKey, attachment };
    } catch (error) {
      if (error instanceof ControlPlaneRejected && [403, 404].includes(error.status)) return null;
      throw error;
    }
  }

  async connectorAttach(uuid: string) {
    try {
      await this.cp.call('POST', `/connectors/${uuid}/attach`, {});
    } catch (error) {
      if (error instanceof ControlPlaneRejected && [403, 404, 409].includes(error.status)) {
        throw new AttachRefused(error.message);
      }
      throw error;
    }
  }

  async connectorDetach(uuid: string) {
    await this.cp.call('POST', `/connectors/${uuid}/detach`, {});
  }

  /** Hub and owner sources of the management VPN; an older API (404) means no hub. */
  async mgmtVpn(): Promise<unknown> {
    try {
      return await this.cp.call<unknown>('GET', '/mgmt-vpn');
    } catch (error) {
      if (error instanceof ControlPlaneRejected && error.status === 404) return { hub: null };
      throw error;
    }
  }

  /** Reports the gateway's WireGuard public key (idempotent). */
  async mgmtVpnKey(publicKey: string) {
    await this.cp.call('POST', '/mgmt-vpn/key', { publicKey });
  }

  heartbeat(body: Record<string, unknown>) {
    return this.cp.call<{ configDigest: string; drain: boolean }>('POST', '/heartbeat', body);
  }

  hostKey(connection: string, body: Parameters<SessionApi['hostKey']>[1]) {
    return this.cp.call<HostKeyResponse>('POST', `/connections/${connection}/hostkey`, body);
  }

  credential(connection: string) {
    return this.cp.call<CredentialResponse>('POST', `/connections/${connection}/credential`, {
      workerReady: true,
    });
  }

  async credentialResult(connection: string, body: Parameters<SessionApi['credentialResult']>[1]) {
    await this.cp.call('POST', `/connections/${connection}/credential/result`, body);
  }

  async events(connection: string, events: RuntimeEvent[]) {
    await this.cp.call('POST', `/connections/${connection}/events`, { events });
  }

  async recordingPart(connection: string, index: number, bytes: Uint8Array, sha256: string) {
    await this.cp.call('PUT', `/connections/${connection}/recording/parts/${index}`, undefined, {
      raw: bytes,
      headers: { 'Content-Type': 'application/x-asciicast', 'X-MNSCloud-Part-SHA256': sha256 },
      timeoutMs: 60000,
    });
  }

  /** Consumes an attach ticket of a live support connection; throws when the API refuses. */
  async attach(connection: string, sha256: string) {
    const data = await this.cp.call<{ role?: unknown } | null>(
      'POST',
      `/connections/${connection}/attach`,
      { sha256 },
    );
    if (data?.role !== 'operator' && data?.role !== 'observer') {
      throw new Error('Invalid attach role');
    }
    return { role: data.role as BrowserRole };
  }

  /** The operator browser left a detachable connection (best effort, audit only). */
  async detach(connection: string) {
    await this.cp.call('POST', `/connections/${connection}/detach`, {});
  }

  /** Result of an exec connection; 1 MiB body cap is kept by the worker. */
  async execResult(connection: string, result: ExecResult) {
    await this.cp.call('POST', `/connections/${connection}/exec-result`, result);
  }

  async finish(connection: string, body: FinishBody) {
    await this.cp.call('POST', `/connections/${connection}/finish`, body);
  }
}
