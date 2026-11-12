// Connector identity: Ed25519 signatures (WebCrypto). The same key signs the API requests of the
// connector and the tunnel handshake toward a gateway; only the public key is known to the
// platform (docs/runtime-api.md, "Remote access connector").

export const REQUEST_SIGNATURE_VERSION = 'mns-connector-v1';
export const TUNNEL_SIGNATURE_VERSION = 'mns-connector-tunnel-v1';

const encoder = new TextEncoder();
const TO_URL: Record<string, string> = { '+': '-', '/': '_' };
const FROM_URL: Record<string, string> = { '-': '+', '_': '/' };
const mapChars = (text: string, map: Record<string, string>) =>
  Array.from(text, (c) => map[c] ?? c).join('');

export function b64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCodePoint(byte);
  const text = mapChars(btoa(binary), TO_URL);
  let end = text.length;
  while (end > 0 && text[end - 1] === '=') end--;
  return text.slice(0, end);
}

export function b64urlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const padded = mapChars(text, FROM_URL) +
    '='.repeat((4 - text.length % 4) % 4);
  try {
    return Uint8Array.from(atob(padded), (c) => c.codePointAt(0)!);
  } catch {
    return null;
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * String signed for an API request:
 * `mns-connector-v1\nMETHOD\npath\ntimestamp\nnonce\nhex(sha256(body))`.
 * `path` is the URL path exactly as sent (including `/api/v1`, without the query string);
 * `timestamp` is unix seconds; the body is the raw request bytes (empty for GET).
 */
export async function requestSigningString(
  method: string,
  path: string,
  timestamp: number | string,
  nonce: string,
  body: Uint8Array,
): Promise<string> {
  return [
    REQUEST_SIGNATURE_VERSION,
    method.toUpperCase(),
    path,
    String(timestamp),
    nonce,
    await sha256Hex(body),
  ].join('\n');
}

/** String signed for the tunnel handshake: `mns-connector-tunnel-v1\n<gateway key>\n<challenge>`. */
export function tunnelSigningString(gatewayKey: string, challenge: string): string {
  return `${TUNNEL_SIGNATURE_VERSION}\n${gatewayKey}\n${challenge}`;
}

export function importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', pkcs8 as Uint8Array<ArrayBuffer>, 'Ed25519', false, [
    'sign',
  ]);
}

export async function signText(key: CryptoKey, text: string): Promise<string> {
  const signature = await crypto.subtle.sign('Ed25519', key, encoder.encode(text));
  return b64urlEncode(new Uint8Array(signature));
}

/** True only for a valid signature by the 32-byte public key (base64url, 43 characters). */
export async function verifyText(
  publicKey: string,
  text: string,
  signature: string,
): Promise<boolean> {
  const raw = b64urlDecode(publicKey);
  const sig = b64urlDecode(signature);
  if (raw?.length !== 32 || sig?.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      raw as Uint8Array<ArrayBuffer>,
      'Ed25519',
      false,
      [
        'verify',
      ],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      sig as Uint8Array<ArrayBuffer>,
      encoder.encode(text),
    );
  } catch {
    return false;
  }
}

/** Fresh Ed25519 pair: PKCS8 private key bytes and the raw public key as base64url. */
export async function generateKeyPair(): Promise<{ pkcs8: Uint8Array; publicKey: string }> {
  const pair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { pkcs8, publicKey: b64urlEncode(raw) };
}

/** "SHA256:" + base64 of sha256(raw public key), as shown in the App. */
export async function publicKeyFingerprint(publicKey: string): Promise<string> {
  const raw = b64urlDecode(publicKey);
  if (!raw) throw new Error('Invalid public key');
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', raw as Uint8Array<ArrayBuffer>),
  );
  let binary = '';
  for (const byte of digest) binary += String.fromCodePoint(byte);
  return `SHA256:${btoa(binary)}`;
}

/** Test and tooling helper: PKCS8 of an Ed25519 key from its 32-byte seed. */
export function pkcs8FromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const prefix = Uint8Array.from([
    0x30,
    0x2e,
    0x02,
    0x01,
    0x00,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    0x04,
    0x22,
    0x04,
    0x20,
  ]);
  const out = new Uint8Array(prefix.length + 32);
  out.set(prefix);
  out.set(seed, prefix.length);
  return out;
}
