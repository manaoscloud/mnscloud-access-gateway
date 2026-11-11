import { parseAssignment, parseConfig } from '../src/controller/contract.ts';
import { AsciicastWriter } from '../src/shared/asciicast.ts';
import { canonicalApi, parseIni } from '../src/controller/control_plane.ts';
import { parseEnv, renderEnv, requireBinding } from '../src/controller/env.ts';
import { credentialFromSecret } from '../src/controller/openvault.ts';
import { assertEquals, assertThrows } from './assert.ts';
import { ASSIGNMENT } from './fixtures.ts';

Deno.test('contract: assignment validation refuses what the gateway must not do', () => {
  assertEquals(parseAssignment(ASSIGNMENT).target, { address: '203.0.113.10', port: 22 });
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, protocol: 'telnet' }), /protocol_refused/);
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, path: 'connector' }), /path_unsupported/);
  assertThrows(
    () => parseAssignment({ ...ASSIGNMENT, target: { address: 'router.example.com', port: 22 } }),
    /address/,
  );
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, username: 'a\nb' }), /username/);
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, ticket: null }), /ticket/);
  assertThrows(() => parseAssignment({ ...ASSIGNMENT, hostKey: { pinned: 'md5:aa' } }), /pin/);
  assertEquals(parseAssignment({ ...ASSIGNMENT, mode: 'test', ticket: null }).ticket, null);
});

Deno.test('contract: config validation', () => {
  const config = parseConfig({
    gatewayUUID: ASSIGNMENT.connectionUUID,
    gatewayKey: 'gw-dev1',
    environment: 'production',
    listen: { address: '10.0.0.20', port: 7443 },
    edgeSources: ['10.0.0.5/32'],
    denylist: ['198.51.100.0/24'],
    labTargets: ['10.1.1.1/32'],
    openvault: { address: 'https://vault.example.internal:8200', caCertificatePem: null },
    configDigest: 'abc',
  });
  assertEquals(config.labTargets, []); // never in production
  assertEquals(config.openvault.address, 'https://vault.example.internal:8200');
  assertThrows(
    () => parseConfig({ ...config, openvault: { address: 'http://vault:8200' } }),
    /OpenVault/,
  );
  assertThrows(() => parseConfig({ ...config, denylist: ['nope'] }), /denylist/);
});

Deno.test('contract: env binding and control plane URL', () => {
  const env = parseEnv(
    'MNSCLOUD_API_BASE_URL=https://api.example.com\nACCESS_GATEWAY_UUID=' +
      ASSIGNMENT.connectionUUID +
      '\nACCESS_GATEWAY_KEY=gw-dev1\nACCESS_GATEWAY_LISTEN_ADDRESS=10.0.0.20\n',
  );
  const binding = requireBinding(env);
  assertEquals(binding.api, 'https://api.example.com/api/v1');
  assertEquals(parseEnv(renderEnv(binding)).ACCESS_GATEWAY_LISTEN_PORT, '7443');
  assertThrows(() => canonicalApi('http://api.example.com'));
  assertThrows(() => canonicalApi('https://user:pw@api.example.com'));
  assertThrows(() => canonicalApi('https://api.example.com/other'));
  assertEquals(
    parseIni('[agent]\napi_base = https://x/api/v1\n[identity]\nagent_uuid_file=/a\n').identity
      .agent_uuid_file,
    '/a',
  );
});

Deno.test('contract: unwrapped KV v1/v2 credential payloads', () => {
  assertEquals(credentialFromSecret({ data: { username: 'u', password: 'p' } }).password, 'p');
  assertEquals(
    credentialFromSecret({ data: { data: { private_key: 'K' }, metadata: {} } }).privateKey,
    'K',
  );
  assertThrows(() => credentialFromSecret({ data: { username: 'u' } }));
});

Deno.test('asciicast: v2 header, output, marker and resize events', () => {
  const w = new AsciicastWriter({ width: 80, height: 24, timestamp: 1000 }, 1000_000);
  assertEquals(JSON.parse(w.headerLine()), {
    version: 2,
    width: 80,
    height: 24,
    timestamp: 1000,
    env: { TERM: 'xterm-256color' },
  });
  assertEquals(JSON.parse(w.output('hi', 1001_500)), [1.5, 'o', 'hi']);
  assertEquals(JSON.parse(w.marker('allowed read: ls', 1002_000)), [2, 'm', 'allowed read: ls']);
  assertEquals(JSON.parse(w.resize(100, 30, 1003_000)), [3, 'r', '100x30']);
});
