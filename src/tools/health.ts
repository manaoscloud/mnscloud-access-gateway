// Validation probe: the controller answers /healthz over TLS with the local certificate.
// Usage: health.ts <env-file>

import { privateRead } from '../controller/control_plane.ts';
import { readEnvFile, requireBinding } from '../controller/env.ts';
import { parseAddress } from '../shared/ip.ts';

if (import.meta.main) {
  try {
    const binding = requireBinding(readEnvFile(Deno.args[0]));
    const cert = privateRead('/etc/mnscloud/access-gateway/tls/cert.pem');
    const client = Deno.createHttpClient({ caCerts: [cert] });
    const host = parseAddress(binding.listenAddress)!.family === 6
      ? `[${binding.listenAddress}]`
      : binding.listenAddress;
    const response = await fetch(`https://${host}:${binding.listenPort}/healthz`, {
      client,
      signal: AbortSignal.timeout(10000),
    });
    const body = await response.json();
    if (!response.ok || body?.status !== 'ok') {
      throw new Error(`listener answered ${response.status} ${body?.status ?? ''}`);
    }
    console.log(`listener ok (version ${body.version}, ${body.activeSessions} active sessions)`);
  } catch (error) {
    console.error(`health check failed: ${(error as Error).message}`);
    Deno.exit(1);
  }
}
