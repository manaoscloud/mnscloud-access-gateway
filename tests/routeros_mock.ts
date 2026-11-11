// RouterOS API-SSL mock (8729 protocol over TLS) for "Testar acesso" tests.

import tls from 'node:tls';
import { encodeSentence, SentenceReader } from '../src/worker/routeros_api.ts';

export interface MockCertificate {
  cert: string;
  key: string;
}

/** Self-signed certificate generated at test time (no key material in the repository). */
export async function makeCertificate(): Promise<MockCertificate> {
  // Key and certificate go to stdout only: nothing is written to disk.
  const out = await new Deno.Command('openssl', {
    args: [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=router',
      '-keyout',
      '/dev/stdout',
      '-out',
      '/dev/stdout',
    ],
    stdout: 'piped',
    stderr: 'null',
  }).output();
  if (!out.success) throw new Error('openssl failed');
  const pem = new TextDecoder().decode(out.stdout);
  const key = /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/.exec(pem)?.[0];
  const cert = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem)?.[0];
  if (!key || !cert) throw new Error('openssl output not understood');
  return { cert: cert + '\n', key: key + '\n' };
}

export interface RouterOsMock {
  port: number;
  sentences: string[][];
  close(): Promise<void>;
}

export function startRouterOs(
  certificate: MockCertificate,
  password: string,
): Promise<RouterOsMock> {
  const sentences: string[][] = [];
  const server = tls.createServer({ cert: certificate.cert, key: certificate.key }, (socket) => {
    const reader = new SentenceReader();
    let authenticated = false;
    socket.on('error', () => {});
    socket.on('data', (chunk: Uint8Array) => {
      for (const words of reader.push(new Uint8Array(chunk))) {
        sentences.push(words);
        const reply = (w: string[]) => socket.write(encodeSentence(w));
        if (words[0] === '/login') {
          if (words.includes(`=password=${password}`) && words.includes('=name=support')) {
            authenticated = true;
            reply(['!done']);
          } else reply(['!trap', '=message=invalid user name or password (6)']);
        } else if (!authenticated) {
          reply(['!fatal', 'not logged in']);
          socket.end();
        } else if (words[0] === '/system/identity/print') {
          reply(['!re', '=name=RB-Lab']);
          reply(['!done']);
        } else if (words[0] === '/system/resource/print') {
          reply([
            '!re',
            '=version=7.24.6 (stable)',
            '=board-name=CHR',
            '=architecture-name=x86_64',
            '=uptime=1d2h',
            '=cpu-load=3',
            '=free-memory=100000',
            '=total-memory=200000',
          ]);
          reply(['!done']);
        } else {
          reply(['!trap', '=message=no such command']);
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: (server.address() as { port: number }).port,
        sentences,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}
