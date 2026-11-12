// Connector identity: signature vectors (the API reuses them), handshake verification at the gateway.

import { signRequest } from '../src/connector/api.ts';
import { ConnectorHub, type HubSocket } from '../src/controller/connector_hub.ts';
import {
  b64urlDecode,
  b64urlEncode,
  generateKeyPair,
  importPrivateKey,
  pkcs8FromSeed,
  publicKeyFingerprint,
  requestSigningString,
  signText,
  tunnelSigningString,
  verifyText,
} from '../src/shared/connector_auth.ts';
import { encodeFrame, FrameType } from '../src/shared/tunnel.ts';
import { assert, assertEquals } from './assert.ts';

// Fixed vector (documented in docs/runtime-api.md). Seed = bytes 0x00..0x1f.
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const PUBLIC_KEY = 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg';
const FINGERPRINT = 'SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=';
const REQUEST_BODY =
  '{"version":"0.1.4","host":"conn-test","addresses":["10.20.30.40"],"tunnelState":"connected"}';
const REQUEST_STRING = 'mns-connector-v1\nPOST\n/api/v1/access/connector/heartbeat\n1767225600\n' +
  'AAAAAAAAAAAAAAAAAAAAAAAA\na5ffc9889f114dd83583f045a6d268af73c983100eafa6b1f29fdfda49110e7e';
const REQUEST_SIGNATURE =
  'r3m4OzeEPpN_UgmO7F8E2eogxE-1__t_3iba29og8UxgDOYPohtnZpqPc_ihHmUpK7o2CuEWIZuvVXKGZwSyCQ';
const CHALLENGE = 'bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2UtMTI';
const TUNNEL_STRING = `mns-connector-tunnel-v1\ngw-dev1\n${CHALLENGE}`;
const TUNNEL_SIGNATURE =
  '2kJt7jDaV6-w8EzMom7VZhtkezpjEZyGNlaonk091NrmAGBdbqEZJGD41GAHWbsMSX7DY2I_8P7oWXle0vhKAw';
const CONNECTOR = '11111111-2222-4333-8444-555555555555';

Deno.test('auth: request signature string and fixed vector', async () => {
  const text = await requestSigningString(
    'post',
    '/api/v1/access/connector/heartbeat',
    1767225600,
    'AAAAAAAAAAAAAAAAAAAAAAAA',
    new TextEncoder().encode(REQUEST_BODY),
  );
  assertEquals(text, REQUEST_STRING);
  const key = await importPrivateKey(pkcs8FromSeed(SEED));
  assertEquals(await signText(key, text), REQUEST_SIGNATURE);
  assert(await verifyText(PUBLIC_KEY, text, REQUEST_SIGNATURE));
  assertEquals(await publicKeyFingerprint(PUBLIC_KEY), FINGERPRINT);
  // Empty body (GET): sha256 of nothing.
  assert(
    (await requestSigningString(
      'GET',
      '/api/v1/access/connector/config',
      1,
      'n'.repeat(16),
      new Uint8Array(0),
    ))
      .endsWith('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
  );
});

Deno.test('auth: tunnel handshake vector', async () => {
  assertEquals(tunnelSigningString('gw-dev1', CHALLENGE), TUNNEL_STRING);
  const key = await importPrivateKey(pkcs8FromSeed(SEED));
  assertEquals(await signText(key, TUNNEL_STRING), TUNNEL_SIGNATURE);
});

Deno.test('auth: signRequest builds the four headers', async () => {
  const key = await importPrivateKey(pkcs8FromSeed(SEED));
  const headers = await signRequest(
    key,
    CONNECTOR,
    'POST',
    '/api/v1/access/connector/heartbeat',
    new TextEncoder().encode(REQUEST_BODY),
    1767225600,
    'AAAAAAAAAAAAAAAAAAAAAAAA',
  );
  assertEquals(headers, {
    'X-MNS-Connector': CONNECTOR,
    'X-MNS-Timestamp': '1767225600',
    'X-MNS-Nonce': 'AAAAAAAAAAAAAAAAAAAAAAAA',
    'X-MNS-Signature': REQUEST_SIGNATURE,
  });
});

Deno.test('auth: bad signature, tampered text, wrong key and malformed input are refused', async () => {
  const other = await generateKeyPair();
  assert(!(await verifyText(PUBLIC_KEY, REQUEST_STRING + 'x', REQUEST_SIGNATURE)), 'body tamper');
  assert(
    !(await verifyText(PUBLIC_KEY, REQUEST_STRING, REQUEST_SIGNATURE.slice(0, -2) + 'AA')),
    'bad sig',
  );
  assert(!(await verifyText(other.publicKey, REQUEST_STRING, REQUEST_SIGNATURE)), 'wrong key');
  assert(!(await verifyText(PUBLIC_KEY, REQUEST_STRING, 'short')), 'short');
  assert(!(await verifyText('not-a-key', REQUEST_STRING, REQUEST_SIGNATURE)), 'bad key');
  assertEquals(b64urlDecode('a*b'), null);
  assertEquals(b64urlEncode(Uint8Array.of(251, 255, 254)), '-__-');
  const pair = await generateKeyPair();
  assertEquals(pair.pkcs8.length, 48);
  assertEquals(b64urlDecode(pair.publicKey)?.length, 32);
});

class FakeSocket implements HubSocket {
  readyState = 1;
  binaryType = 'blob';
  sent: (string | Uint8Array)[] = [];
  closed: [number, string] | null = null;
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  send(data: string | Uint8Array) {
    this.sent.push(data);
  }
  close(code = 1000, reason = '') {
    if (this.closed) return;
    this.closed = [code, reason];
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.({} as CloseEvent));
  }
  receive(data: string | Uint8Array) {
    this.onmessage?.({ data } as MessageEvent);
  }
  text(index = 0) {
    const text = this.sent.filter((s) => typeof s === 'string')[index];
    return text ? JSON.parse(text as string) : null;
  }
}

function hubFor(publicKeys: Record<string, string>) {
  const calls: string[] = [];
  const hub = new ConnectorHub({
    gatewayKey: 'gw-dev1',
    api: {
      connector: (uuid) => {
        calls.push(`get:${uuid}`);
        return Promise.resolve(publicKeys[uuid] ? { publicKey: publicKeys[uuid] } : null);
      },
      connectorAttach: (uuid) => {
        calls.push(`attach:${uuid}`);
        return Promise.resolve();
      },
      connectorDetach: (uuid) => {
        calls.push(`detach:${uuid}`);
        return Promise.resolve();
      },
    },
    maxStreams: () => 4,
    log: () => {},
    handshakeTimeoutMs: 200,
  });
  return { hub, calls };
}

const settle = () => new Promise((r) => setTimeout(r, 30));

async function connect(
  hub: ConnectorHub,
  seed: Uint8Array,
  gatewayKey = 'gw-dev1',
  uuid = CONNECTOR,
) {
  const socket = new FakeSocket();
  hub.attach(socket);
  const challenge = socket.text()!.challenge as string;
  const key = await importPrivateKey(pkcs8FromSeed(seed));
  socket.receive(JSON.stringify({
    t: 'hello',
    connectorUuid: uuid,
    signature: await signText(key, tunnelSigningString(gatewayKey, challenge)),
  }));
  await settle();
  return socket;
}

Deno.test('hub: good handshake attaches, answers ready and detaches on close', async () => {
  const { hub, calls } = hubFor({ [CONNECTOR]: PUBLIC_KEY });
  const socket = await connect(hub, SEED);
  assertEquals(socket.binaryType, 'arraybuffer');
  assertEquals(socket.text(0)!.t, 'challenge');
  assertEquals(socket.text(0)!.challenge.length, 43);
  assertEquals(socket.text(1), { t: 'ready', maxStreams: 4, window: 262144 });
  assertEquals(calls, [`get:${CONNECTOR}`, `attach:${CONNECTOR}`]);
  assert(hub.has(CONNECTOR));
  socket.close();
  await settle();
  assert(!hub.has(CONNECTOR));
  assertEquals(calls.at(-1), `detach:${CONNECTOR}`);
});

Deno.test('hub: wrong key, wrong gateway key, unknown connector and garbage are refused', async () => {
  const { hub, calls } = hubFor({ [CONNECTOR]: PUBLIC_KEY });
  const wrongKey = await connect(hub, Uint8Array.from({ length: 32 }, (_, i) => 100 + i));
  assertEquals(wrongKey.closed?.[0], 4401);
  const wrongGateway = await connect(hub, SEED, 'gw-other');
  assertEquals(wrongGateway.closed?.[0], 4401);
  const unknown = await connect(hub, SEED, 'gw-dev1', '99999999-2222-4333-8444-555555555555');
  assertEquals(unknown.closed?.[0], 4401);
  const garbage = new FakeSocket();
  hub.attach(garbage);
  garbage.receive('{not json');
  await settle();
  assertEquals(garbage.closed?.[0], 4401);
  const binary = new FakeSocket();
  hub.attach(binary);
  binary.receive(new Uint8Array([1, 2, 3]));
  assertEquals(binary.closed?.[0], 4400);
  assert(!calls.some((c) => c.startsWith('attach:')), 'nothing was attached');
  assert(!hub.has(CONNECTOR));
});

Deno.test('hub: silence is cut after the handshake timeout', async () => {
  const { hub } = hubFor({});
  const socket = new FakeSocket();
  hub.attach(socket);
  await new Promise((r) => setTimeout(r, 300));
  assertEquals(socket.closed?.[0], 4408);
});

Deno.test('hub: a new authenticated tunnel replaces the old one without detaching', async () => {
  const { hub, calls } = hubFor({ [CONNECTOR]: PUBLIC_KEY });
  const first = await connect(hub, SEED);
  const second = await connect(hub, SEED);
  await settle();
  assertEquals(first.closed?.[0], 4409);
  assertEquals(second.closed, null);
  assert(hub.has(CONNECTOR));
  assertEquals(calls.filter((c) => c.startsWith('detach:')).length, 0);
});

Deno.test('hub: a connector that sends OPEN loses its tunnel', async () => {
  const { hub, calls } = hubFor({ [CONNECTOR]: PUBLIC_KEY });
  const socket = await connect(hub, SEED);
  socket.receive(encodeFrame(FrameType.OPEN, 1, new TextEncoder().encode('{}')));
  await settle();
  assertEquals(socket.closed?.[0], 4400);
  assert(!hub.has(CONNECTOR));
  assertEquals(calls.at(-1), `detach:${CONNECTOR}`);
});

Deno.test('hub: attach refusal closes the tunnel', async () => {
  const hub = new ConnectorHub({
    gatewayKey: 'gw-dev1',
    api: {
      connector: () => Promise.resolve({ publicKey: PUBLIC_KEY }),
      connectorAttach: () => Promise.reject(new Error('no')),
      connectorDetach: () => Promise.resolve(),
    },
    maxStreams: () => 1,
    log: () => {},
  });
  const socket = await connect(hub, SEED);
  assertEquals(socket.closed?.[0], 4503);
  assert(!hub.has(CONNECTOR));
});

Deno.test('hub: open() without a tunnel is connector_offline', async () => {
  const { hub } = hubFor({});
  try {
    await hub.open(CONNECTOR, { connectionUuid: CONNECTOR, host: '10.0.0.1', port: 22 });
    throw new Error('expected a rejection');
  } catch (error) {
    assertEquals((error as Error).message, 'connector_offline');
  }
});
