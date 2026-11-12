// Connector configuration: the local file written at installation and the remote configuration
// the API returns on every poll (`GET /access/connector/config`).

import { canonicalApi } from '../controller/control_plane.ts';
import { UUID } from '../controller/contract.ts';
import { b64urlDecode } from '../shared/connector_auth.ts';
import { type Cidr } from '../shared/ip.ts';
import { parseAllowedCidrs } from '../shared/destination.ts';

export const DEFAULT_CONFIG_PATH = '/etc/mnscloud-access-connector/connector.json';

export interface LocalConfig {
  apiUrl: string;
  connectorUuid: string;
  keyFile: string;
}

export function parseLocalConfig(text: string): LocalConfig {
  const value = JSON.parse(text);
  const keyFile = String(value?.keyFile ?? '');
  if (!UUID.test(String(value?.connectorUuid))) throw new Error('Invalid connectorUuid');
  if (!/^\/[A-Za-z0-9._/-]{1,200}$/.test(keyFile) || keyFile.includes('..')) {
    throw new Error('Invalid keyFile');
  }
  return {
    apiUrl: canonicalApi(String(value?.apiUrl ?? '')),
    connectorUuid: value.connectorUuid,
    keyFile,
  };
}

/** Reads the private key file (base64 PKCS8): regular file, not group/other accessible, owned by us. */
export function readPrivateKeyFile(path: string): Uint8Array {
  const info = Deno.lstatSync(path);
  if (!info.isFile || info.isSymlink || info.size > 4096) throw new Error('Unsafe key file');
  if (Deno.build.os === 'linux') {
    const uid = Deno.uid();
    if (((info.mode ?? 0) & 0o077) !== 0 || (uid !== null && info.uid !== uid && uid !== 0)) {
      throw new Error('Unsafe key file');
    }
  }
  const bytes = b64urlDecode(Deno.readTextFileSync(path).trim());
  if (bytes?.length !== 48) throw new Error('Invalid key file');
  return bytes;
}

export interface GatewayTarget {
  key: string;
  /** Full `wss://` URL of `/access-gateway/<key>/connector`. */
  relayUrl: string;
}

export interface RemoteConfig {
  allowedCidrs: Cidr[];
  gateway: GatewayTarget | null;
  release: { tag: string; commit: string } | null;
}

const GATEWAY_KEY = /^[a-z0-9][a-z0-9-]{1,62}$/;

/** Validates the relay URL: wss only, no credentials, no query, exactly the connector path. */
export function relayUrlFor(key: string, relayUrl: unknown, relayPath: unknown, apiUrl: string) {
  let url: URL;
  try {
    url = typeof relayUrl === 'string'
      ? new URL(relayUrl)
      : new URL(typeof relayPath === 'string' ? relayPath : '', new URL(apiUrl).origin);
  } catch {
    return null;
  }
  if (
    url.protocol !== 'wss:' && !(url.protocol === 'https:' && typeof relayUrl !== 'string')
  ) return null;
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== `/access-gateway/${key}/connector`) return null;
  url.protocol = 'wss:';
  return url.toString();
}

/** Parses `data` of the config response; null when it does not match the contract. */
export function parseRemoteConfig(value: unknown, apiUrl: string): RemoteConfig | null {
  // deno-lint-ignore no-explicit-any
  const v = value as Record<string, any>;
  if (!v || typeof v !== 'object') return null;
  const allowedCidrs = parseAllowedCidrs(v.allowedCidrs);
  if (allowedCidrs === null) return null;
  let gateway: GatewayTarget | null = null;
  if (v.gateway) {
    const key = String(v.gateway.key ?? '');
    if (!GATEWAY_KEY.test(key)) return null;
    const relayUrl = relayUrlFor(key, v.gateway.relayUrl, v.gateway.relayPath, apiUrl);
    if (!relayUrl) return null;
    gateway = { key, relayUrl };
  }
  let release: RemoteConfig['release'] = null;
  if (v.release) {
    if (!/^v\d{1,4}\.\d{1,4}\.\d{1,5}$/.test(String(v.release.tag))) return null;
    if (!/^[0-9a-f]{40}$/.test(String(v.release.commit))) return null;
    release = { tag: v.release.tag, commit: v.release.commit };
  }
  return { allowedCidrs, gateway, release };
}
