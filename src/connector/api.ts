// Signed client of `/api/v1/access/connector/*`. The connector holds no platform secret: every
// request carries an Ed25519 signature made with the key that never left this host.
//
//   X-MNS-Connector: <uuid>   X-MNS-Timestamp: <unix s>   X-MNS-Nonce: <16-64 url-safe chars>
//   X-MNS-Signature: base64url(Ed25519("mns-connector-v1\nMETHOD\npath\nts\nnonce\nhex(sha256(body))"))

import { b64urlEncode, requestSigningString, signText } from '../shared/connector_auth.ts';

const MAX_RESPONSE = 1024 * 1024;

export class ApiRejected extends Error {
  constructor(readonly status: number) {
    super(`The API rejected the request (HTTP ${status})`);
  }
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface SignedRequestParts {
  headers: Record<string, string>;
  body: Uint8Array;
}

export async function signRequest(
  key: CryptoKey,
  connectorUuid: string,
  method: string,
  path: string,
  body: Uint8Array,
  timestamp: number,
  nonce: string,
): Promise<Record<string, string>> {
  const text = await requestSigningString(method, path, timestamp, nonce, body);
  return {
    'X-MNS-Connector': connectorUuid,
    'X-MNS-Timestamp': String(timestamp),
    'X-MNS-Nonce': nonce,
    'X-MNS-Signature': await signText(key, text),
  };
}

export class ConnectorApi {
  constructor(
    private readonly apiUrl: string,
    private readonly connectorUuid: string,
    private readonly key: CryptoKey,
    private readonly fetchImpl: FetchLike = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  async call<T>(method: string, route: string, body?: unknown, timeoutMs = 20000): Promise<T> {
    const url = new URL(this.apiUrl + route);
    const payload = body === undefined
      ? new Uint8Array(0)
      : new TextEncoder().encode(JSON.stringify(body));
    const nonce = b64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
    const signed = await signRequest(
      this.key,
      this.connectorUuid,
      method,
      url.pathname,
      payload,
      Math.floor(this.now() / 1000),
      nonce,
    );
    const response = await this.fetchImpl(url.toString(), {
      method,
      headers: {
        ...signed,
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : payload as Uint8Array<ArrayBuffer>,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (response.status >= 300 && response.status < 400) throw new ApiRejected(response.status);
    if (!response.ok) throw new ApiRejected(response.status);
    if (bytes.length > MAX_RESPONSE || !bytes.length) return null as T;
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return (parsed && typeof parsed === 'object' && 'data' in parsed ? parsed.data : null) as T;
  }

  heartbeat(body: {
    version: string;
    host: string;
    addresses: string[];
    tunnelState: 'connected' | 'disconnected';
  }) {
    return this.call('POST', '/access/connector/heartbeat', body);
  }

  config() {
    return this.call<unknown>('GET', '/access/connector/config');
  }

  /** True only when the API confirms this exact connection for this connector. */
  async accept(connectionUuid: string, destination: string, port: number): Promise<boolean> {
    await this.call('POST', `/access/connector/connections/${connectionUuid}/accept`, {
      destination,
      port,
    });
    return true;
  }
}

/** Unsigned claim: the single-use install token is the only authentication. */
export async function claim(
  apiUrl: string,
  body: { token: string; publicKey: string; host: string; version: string },
  fetchImpl: FetchLike = fetch,
): Promise<{ connectorUuid: string }> {
  const response = await fetchImpl(`${apiUrl}/access/connector/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(30000),
  });
  const text = await response.text();
  if (!response.ok) throw new ApiRejected(response.status);
  const data = JSON.parse(text)?.data;
  if (typeof data?.connectorUuid !== 'string') throw new Error('Invalid claim response');
  return { connectorUuid: data.connectorUuid };
}
