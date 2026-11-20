// Synthetic WinRM HTTPS endpoint (WS-Man / WinRS cmd shell) for the tests. It speaks the wire
// protocol the gateway implements (Create, Command, Receive, Signal, Delete, Basic auth, SOAP
// faults) and can misbehave on purpose. It is a protocol simulator: nothing here proves that a
// real Windows host, WinRM listener or firmware behaves this way.

import { Buffer } from 'node:buffer';
import https from 'node:https';
import { type MockCertificate } from './routeros_mock.ts';

export interface WinrmReply {
  stdout?: string;
  stderr?: string;
  /** Raw bytes for stdout (overrides `stdout`). */
  stdoutBytes?: Uint8Array;
  exit?: number;
  /** Receive answers with the operation timeout fault this many times first. */
  slowReceives?: number;
}

export interface WinrmMockOptions {
  user?: string;
  /** Adversarial response mutation for real-worker protocol checks. */
  transformResponse?: (xml: string, action: string) => string;
  password: string;
  commands?: Record<string, WinrmReply>;
  /** Behaviour for a command line that is not in `commands`. */
  fallback?: (line: string) => WinrmReply;
  /** A command (regexp) whose Receive never completes (operation timeout fault, 250 ms apart). */
  hang?: RegExp;
  failCreate?:
    | 'fault'
    | 'redirect'
    | 'html'
    | 'bad-shell-id'
    | 'dtd'
    | 'big-header'
    | 'wrong-relates'
    | 'no-keepalive';
  failReceive?: 'fault' | 'wrong-command-id' | 'bad-base64' | 'wrong-stream' | 'dtd';
  chunked?: boolean;
  /** The server answers every request with 401. */
  denyAll?: boolean;
}

export interface RecordedRequest {
  path: string;
  action: string;
  authorization: string | null;
  contentType: string | null;
  body: string;
}

export interface WinrmMock {
  port: number;
  requests: RecordedRequest[];
  /** Command lines started, in order. */
  commands: string[];
  signals: string[];
  deletes: string[];
  connections: number;
  openShells: Set<string>;
  /** Number of distinct TCP connections that sent at least one HTTP request. */
  close(): Promise<void>;
}

const SOAP = 'application/soap+xml;charset=UTF-8';
const ACTIONS: Record<string, string> = {
  'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create': 'create',
  'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete': 'delete',
  'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command': 'command',
  'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive': 'receive',
  'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal': 'signal',
};
const NS =
  'xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"';
const unescape = (v: string) =>
  v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
const b64 = (bytes: Uint8Array | string) =>
  Buffer.from(typeof bytes === 'string' ? bytes : bytes).toString('base64');

export function startWinrm(
  certificate: MockCertificate,
  options: WinrmMockOptions,
): Promise<WinrmMock> {
  const mock: WinrmMock = {
    port: 0,
    requests: [],
    commands: [],
    signals: [],
    deletes: [],
    connections: 0,
    openShells: new Set(),
    close: () => Promise.resolve(),
  };
  const commandsById = new Map<
    string,
    { line: string; reply: WinrmReply; receives: number; done: boolean }
  >();
  const expected = 'Basic ' + Buffer.from(`${options.user ?? 'support'}:${options.password}`)
    .toString('base64');

  const server = https.createServer(
    { cert: certificate.cert, key: certificate.key },
    (req, res) => {
      const chunks: Uint8Array[] = [];
      req.on('data', (c: Uint8Array) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        const requestAction = /<a:Action[^>]*>([^<]+)<\/a:Action>/.exec(body)?.[1] ?? '';
        const action = ACTIONS[requestAction] ?? 'unknown';
        mock.requests.push({
          path: req.url ?? '',
          action,
          authorization: req.headers.authorization ?? null,
          contentType: req.headers['content-type'] ?? null,
          body,
        });
        const send = (
          status: number,
          text: string,
          extra: Record<string, string | number> = {},
          type = SOAP,
        ) => {
          if (options.transformResponse && type === SOAP) {
            text = options.transformResponse(text, action);
          }
          const headers: Record<string, string | number> = {
            'Content-Type': type,
            ...(options.chunked ? {} : { 'Content-Length': Buffer.byteLength(text) }),
            ...extra,
          };
          res.writeHead(status, headers);
          res.end(text);
        };
        if (options.denyAll || req.headers.authorization !== expected) {
          send(
            401,
            '',
            { 'WWW-Authenticate': 'Basic realm="WSMAN"', 'Content-Length': 0 },
            'text/plain',
          );
          return;
        }
        if (req.url !== '/wsman' || req.method !== 'POST') {
          send(404, '', {}, 'text/plain');
          return;
        }
        const messageId = /<a:MessageID>([^<]+)<\/a:MessageID>/.exec(body)?.[1] ?? '';
        const shellSelector = /<w:Selector Name="ShellId">([^<]+)<\/w:Selector>/.exec(body)?.[1] ??
          '';
        const envelope = (inner: string, relates = messageId) =>
          `<?xml version="1.0" encoding="UTF-8"?><s:Envelope ${NS}><s:Header><a:Action>${
            inner.includes('<s:Fault>')
              ? 'http://schemas.dmtf.org/wbem/wsman/1/wsman/fault'
              : requestAction + 'Response'
          }</a:Action><a:RelatesTo>${relates}</a:RelatesTo></s:Header><s:Body>${inner}</s:Body></s:Envelope>`;
        const fault = (code: string, text = 'The operation failed') =>
          envelope(
            `<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">${text}</s:Text></s:Reason><s:Detail><f:WSManFault Code="${code}"><f:Message>${text}</f:Message></f:WSManFault></s:Detail></s:Fault>`,
          );

        if (action === 'create') {
          switch (options.failCreate) {
            case 'fault':
              return send(500, fault('2150859046', 'WinRS client cannot process the request'));
            case 'redirect':
              return send(307, '', { Location: 'https://evil.example/wsman', 'Content-Length': 0 });
            case 'html':
              return send(200, '<html>nope</html>', {}, 'text/html');
            case 'dtd':
              return send(
                200,
                '<?xml version="1.0"?><!DOCTYPE s [<!ENTITY a "bbbbbbbb">]><s:Envelope ' + NS +
                  '/>',
              );
            case 'big-header':
              return send(200, envelope(''), { 'X-Pad': 'a'.repeat(20000) });
            case 'wrong-relates':
              return send(200, envelope('', 'uuid:00000000-0000-0000-0000-000000000000'));
          }
          const id = options.failCreate === 'bad-shell-id'
            ? 'not-a-guid'
            : crypto.randomUUID().toUpperCase();
          mock.openShells.add(id);
          return send(
            200,
            envelope(`<rsp:Shell><rsp:ShellId>${id}</rsp:ShellId></rsp:Shell>`),
            options.failCreate === 'no-keepalive' ? { Connection: 'close' } : {},
          );
        }
        if (!mock.openShells.has(shellSelector)) {
          return send(500, fault('2150858843', 'The shell does not exist'));
        }
        if (action === 'command') {
          const line = unescape(/<rsp:Command>([^<]*)<\/rsp:Command>/.exec(body)?.[1] ?? '');
          mock.commands.push(line);
          const id = crypto.randomUUID().toUpperCase();
          const reply = options.commands?.[line] ?? options.fallback?.(line) ??
            { stdout: '', exit: 0 };
          commandsById.set(id, { line, reply, receives: 0, done: false });
          return send(
            200,
            envelope(
              `<rsp:CommandResponse><rsp:CommandId>${id}</rsp:CommandId></rsp:CommandResponse>`,
            ),
          );
        }
        if (action === 'receive') {
          const id = /CommandId="([^"]+)"/.exec(body)?.[1] ?? '';
          const command = commandsById.get(id);
          if (!command) return send(500, fault('2150858843', 'No such command'));
          command.receives++;
          if (options.failReceive === 'fault') {
            return send(500, fault('2150858780', 'Receive failed'));
          }
          if (options.failReceive === 'dtd') {
            return send(
              200,
              '<?xml version="1.0"?><!DOCTYPE s [<!ENTITY a "b">]><s:Envelope ' + NS + '/>',
            );
          }
          if (
            (options.hang && options.hang.test(command.line)) ||
            command.receives <= (command.reply.slowReceives ?? 0)
          ) {
            setTimeout(() => send(500, fault('2150858793', 'The operation timed out')), 250);
            return;
          }
          const out = command.reply.stdoutBytes ?? Buffer.from(command.reply.stdout ?? '');
          const streams = (out.length
            ? `<rsp:Stream Name="${
              options.failReceive === 'wrong-stream' ? 'stdin' : 'stdout'
            }" CommandId="${
              options.failReceive === 'wrong-command-id' ? crypto.randomUUID().toUpperCase() : id
            }">${options.failReceive === 'bad-base64' ? '@@@@' : b64(out)}</rsp:Stream>`
            : '') + (command.reply.stderr
              ? `<rsp:Stream Name="stderr" CommandId="${id}">${
                b64(command.reply.stderr)
              }</rsp:Stream>`
              : '');
          command.done = true;
          return send(
            200,
            envelope(
              `<rsp:ReceiveResponse>${streams}<rsp:CommandState CommandId="${id}" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>${
                command.reply.exit ?? 0
              }</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`,
            ),
          );
        }
        if (action === 'signal') {
          const id = /CommandId="([^"]+)"/.exec(body)?.[1] ?? '';
          mock.signals.push(commandsById.get(id)?.line ?? '?');
          return send(200, envelope(''));
        }
        if (action === 'delete') {
          mock.deletes.push(shellSelector);
          mock.openShells.delete(shellSelector);
          return send(200, envelope(''));
        }
        send(500, fault('2150858770', 'Unknown action'));
      });
    },
  );
  server.on('connection', () => mock.connections++);
  server.on('tlsClientError', () => {});
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      mock.port = (server.address() as { port: number }).port;
      mock.close = () =>
        new Promise<void>((r) => {
          server.closeAllConnections?.();
          server.close(() => r());
        });
      resolve(mock);
    });
  });
}
