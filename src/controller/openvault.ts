// OpenVault (OpenBao) response-wrapping unwrap. The API hands the gateway a single-use wrapping
// token (TTL of seconds) for exactly one connection; the gateway exchanges it at the configured
// OpenVault address and passes the secret to the worker. Nothing is written to disk or logged.

import type { WorkerCredential } from '../shared/ipc.ts';

export class UnwrapError extends Error {}

export type Unwrapper = (wrapToken: string) => Promise<Omit<WorkerCredential, 't'>>;

const TOKEN = /^[A-Za-z0-9._-]{16,512}$/;

/** Picks the credential fields from a KV v1/v2 payload. */
export function credentialFromSecret(payload: unknown): Omit<WorkerCredential, 't'> {
  const outer = (payload as { data?: Record<string, unknown> })?.data;
  const data =
    (outer && typeof outer.data === 'object' && outer.data !== null ? outer.data : outer) as
      | Record<string, unknown>
      | undefined;
  if (!data) throw new UnwrapError('Empty secret');
  const pick = (
    key: string,
  ) => (typeof data[key] === 'string' && data[key] ? String(data[key]) : undefined);
  const credential = {
    username: pick('username'),
    password: pick('password'),
    privateKey: pick('privateKey') ?? pick('private_key'),
    passphrase: pick('passphrase'),
  };
  if (!credential.password && !credential.privateKey) {
    throw new UnwrapError('Secret has no usable credential');
  }
  return credential;
}

export function openVaultUnwrapper(address: string, caCertificatePem: string | null): Unwrapper {
  const client = caCertificatePem
    ? Deno.createHttpClient({ caCerts: [caCertificatePem] })
    : undefined;
  return async (wrapToken) => {
    if (!TOKEN.test(wrapToken)) throw new UnwrapError('Invalid wrapping token');
    const response = await fetch(`${address}/v1/sys/wrapping/unwrap`, {
      method: 'POST',
      headers: { 'X-Vault-Token': wrapToken, 'Content-Type': 'application/json' },
      body: '{}',
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
      ...(client ? { client } : {}),
    });
    const text = await response.text();
    if (!response.ok) throw new UnwrapError(`Unwrap refused (HTTP ${response.status})`);
    if (text.length > 65536) throw new UnwrapError('Oversized secret');
    return credentialFromSecret(JSON.parse(text));
  };
}
