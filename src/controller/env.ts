// Node binding written by the installation ceremony (/etc/mnscloud/access-gateway.env, 0600).
// It holds no secret: only the control plane, the gateway identity and the listener.

import { parseAddress } from '../shared/ip.ts';
import { canonicalApi, privateRead } from './control_plane.ts';
import { UUID } from './contract.ts';

export const DEFAULT_ENV = '/etc/mnscloud/access-gateway.env';

export function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error('Invalid environment line');
    out[match[1]] = match[2].replace(/^"(.*)"$/, '$1');
  }
  return out;
}

export function readEnvFile(path = DEFAULT_ENV): Record<string, string> {
  return parseEnv(privateRead(path));
}

export interface Binding {
  api: string;
  gatewayUUID: string;
  gatewayKey: string;
  listenAddress: string;
  listenPort: number;
}

export function requireBinding(env: Record<string, string>): Binding {
  const api = canonicalApi(env.MNSCLOUD_API_BASE_URL ?? '');
  const gatewayUUID = env.ACCESS_GATEWAY_UUID ?? '';
  const gatewayKey = env.ACCESS_GATEWAY_KEY ?? '';
  const listen = parseAddress(env.ACCESS_GATEWAY_LISTEN_ADDRESS);
  const port = Number(env.ACCESS_GATEWAY_LISTEN_PORT ?? 7443);
  if (!UUID.test(gatewayUUID)) throw new Error('Invalid ACCESS_GATEWAY_UUID');
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(gatewayKey)) throw new Error('Invalid ACCESS_GATEWAY_KEY');
  if (!listen) throw new Error('Invalid ACCESS_GATEWAY_LISTEN_ADDRESS');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('Invalid ACCESS_GATEWAY_LISTEN_PORT');
  }
  return { api, gatewayUUID, gatewayKey, listenAddress: listen.text, listenPort: port };
}

/** Renders the binding file from installation material (bootstrap). */
export function renderEnv(binding: Binding): string {
  return [
    `MNSCLOUD_API_BASE_URL=${binding.api}`,
    `ACCESS_GATEWAY_UUID=${binding.gatewayUUID}`,
    `ACCESS_GATEWAY_KEY=${binding.gatewayKey}`,
    `ACCESS_GATEWAY_LISTEN_ADDRESS=${binding.listenAddress}`,
    `ACCESS_GATEWAY_LISTEN_PORT=${binding.listenPort}`,
    '',
  ].join('\n');
}
