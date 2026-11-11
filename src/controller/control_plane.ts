// Agent-authenticated client of the MNSCloud control plane (`/api/v1/access/runtime/*`).
// The gateway holds no API credential of its own: every call carries the identity of the enrolled
// Agent of the same host, read from root-only files, and the API rejects it unless that Agent is
// bound to this access gateway (same model as mnscloud-dns/scripts/control_plane.py).
// Response bodies and tokens are never logged.

export const AGENT_CONF = '/etc/mnscloud/agent/agent.conf';
const MAX_RESPONSE = 4 * 1024 * 1024;
export const RUNTIME_PREFIX = '/access/runtime';

export class ControlPlaneRejected extends Error {
  constructor(readonly status: number, readonly code: string, hint = '') {
    super(`Control plane rejected the request (HTTP ${status}${code ? ' ' + code : ''})${hint}`);
  }
}

const HINTS: Record<string, string> = {
  ACCESS_GATEWAY_AGENT_FORBIDDEN:
    '; the host Agent must be active and belong to an environment of the platform master who generated this command',
  ACCESS_GATEWAY_INSTALLATION_EXPIRED:
    '; the command expired or was replaced; generate a new command in the App',
  ACCESS_GATEWAY_ALREADY_BOUND:
    '; this gateway or this Agent is already bound to an access gateway installation',
  ACCESS_GATEWAY_ADDRESS_INVALID:
    '; the listen address must be a private address reported by the host Agent (wait for the next Agent heartbeat, then rerun)',
  ACCESS_GATEWAY_TRANSITION_INVALID:
    '; use Retry installation in the App, then rerun the resume command',
};

/** Reads a root-owned private file (no symlink, mode 0600 or stricter, bounded size). */
export function privateRead(path: string, maxBytes = 65536): string {
  const info = Deno.lstatSync(path);
  if (!info.isFile || info.isSymlink) throw new Error('Unsafe private file');
  if (Deno.build.os === 'linux') {
    if (info.uid !== 0 || ((info.mode ?? 0) & 0o077) !== 0) throw new Error('Unsafe private file');
  }
  if (info.size > maxBytes) throw new Error('Unsafe private file');
  return Deno.readTextFileSync(path);
}

export function parseIni(text: string): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  let section = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      section = header[1].trim();
      out[section] ??= {};
      continue;
    }
    const sep = line.search(/[=:]/);
    if (sep < 0) continue;
    (out[section] ??= {})[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
  }
  return out;
}

export function canonicalApi(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('A trusted HTTPS control plane is required');
  }
  if (
    url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search ||
    url.hash
  ) {
    throw new Error('A trusted HTTPS control plane is required');
  }
  const path = url.pathname.replace(/\/+$/, '');
  if (!['', '/api', '/api/v1'].includes(path)) throw new Error('Invalid control plane path');
  return `${url.protocol}//${url.host}/api/v1`;
}

export interface AgentIdentity {
  api: string;
  uuid: string;
  token: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Identity of the host Agent; refuses when the Agent trusts another control plane. */
export function loadAgentIdentity(api: string, conf = AGENT_CONF): AgentIdentity {
  const ini = parseIni(privateRead(conf));
  const local = canonicalApi(ini.agent?.api_base ?? '');
  if (local !== canonicalApi(api)) {
    throw new Error('Access gateway and Agent control planes differ');
  }
  const uuid = privateRead(ini.identity?.agent_uuid_file ?? '/var/lib/mnscloud/agent/agent.uuid')
    .trim();
  if (!UUID.test(uuid)) throw new Error('Invalid Agent identity');
  const token = privateRead(ini.identity?.agent_token_file ?? '/var/lib/mnscloud/agent/agent.token')
    .trim();
  if (!token || /\s/.test(token)) throw new Error('Invalid Agent identity');
  return { api: local, uuid, token };
}

export interface CallOptions {
  raw?: Uint8Array;
  headers?: Record<string, string>;
  timeoutMs?: number;
  query?: Record<string, string | number>;
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export class ControlPlane {
  constructor(
    private readonly identity: AgentIdentity,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}

  get agentUUID() {
    return this.identity.uuid;
  }

  async call<T>(
    method: string,
    path: string,
    body?: unknown,
    options: CallOptions = {},
  ): Promise<T> {
    const query = options.query
      ? '?' +
        new URLSearchParams(Object.entries(options.query).map(([k, v]) => [k, String(v)]))
          .toString()
      : '';
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.identity.token}`,
      'X-MNSCloud-Agent-UUID': this.identity.uuid,
      Accept: 'application/json',
      ...(options.headers ?? {}),
    };
    let payload: BodyInit | undefined;
    if (options.raw) payload = options.raw as Uint8Array<ArrayBuffer>;
    else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const response = await this.fetchImpl(this.identity.api + RUNTIME_PREFIX + path + query, {
      method,
      headers,
      body: payload,
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs ?? 30000),
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new Error('Control plane redirects are forbidden');
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > MAX_RESPONSE) throw new Error('Oversized control plane response');
    if (!response.ok) {
      let code = '';
      try {
        const parsed = JSON.parse(new TextDecoder().decode(bytes.slice(0, 4096)));
        const candidate = parsed?.code ?? parsed?.error;
        if (typeof candidate === 'string' && /^ACCESS_GATEWAY_[A-Z_]{1,60}$/.test(candidate)) {
          code = candidate;
        }
      } catch { /* not JSON */ }
      throw new ControlPlaneRejected(response.status, code, HINTS[code] ?? '');
    }
    if (!bytes.length) return null as T;
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return (parsed && typeof parsed === 'object' && 'data' in parsed ? parsed.data : null) as T;
  }
}
