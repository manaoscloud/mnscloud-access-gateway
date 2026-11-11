// Worker entry point. Started by the controller inside the session sandbox:
//   deno run --cached-only --frozen --no-prompt --allow-net=<ip>:<port> --allow-read=<runtime>
//        src/worker/main.ts
// stdin/stdout carry the JSON-line protocol of src/shared/ipc.ts; nothing else is printed.

import { encodeMessage, readMessages, type WorkerToController } from '../shared/ipc.ts';
import { runWorker } from './worker.ts';

const encoder = new TextEncoder();
const writer = Deno.stdout.writable.getWriter();
let chain = Promise.resolve();

function send(message: WorkerToController) {
  const bytes = encoder.encode(encodeMessage(message));
  chain = chain.then(() => writer.write(bytes)).catch(() => {});
}

if (import.meta.main) {
  let code = 0;
  try {
    const exit = await runWorker({ messages: readMessages(Deno.stdin.readable), send });
    code = exit.state === 'closed' ? 0 : 1;
  } catch {
    send({ t: 'exit', state: 'failed', reason: 'worker_failed', bytesIn: 0, bytesOut: 0 });
    code = 1;
  }
  await chain;
  Deno.exit(code);
}
