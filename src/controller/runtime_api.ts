// SessionApi and controller calls over the Agent-authenticated control plane.

import type {
  AssignmentsResponse,
  CredentialResponse,
  FinishBody,
  HostKeyResponse,
} from './contract.ts';
import { type ControlPlane, ControlPlaneRejected } from './control_plane.ts';
import type { ConnectorRuntimeApi } from './connector_hub.ts';
import type { RuntimeEvent, SessionApi } from './session.ts';

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
      const data = await this.cp.call<{ publicKey?: unknown } | null>('GET', `/connectors/${uuid}`);
      return typeof data?.publicKey === 'string' ? { publicKey: data.publicKey } : null;
    } catch (error) {
      if (error instanceof ControlPlaneRejected && [403, 404].includes(error.status)) return null;
      throw error;
    }
  }

  async connectorAttach(uuid: string) {
    await this.cp.call('POST', `/connectors/${uuid}/attach`, {});
  }

  async connectorDetach(uuid: string) {
    await this.cp.call('POST', `/connectors/${uuid}/detach`, {});
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

  async finish(connection: string, body: FinishBody) {
    await this.cp.call('POST', `/connections/${connection}/finish`, body);
  }
}
