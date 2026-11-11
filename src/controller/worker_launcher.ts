// Starts a session worker and exposes its JSON-line pipes. Production runs it through
// systemd-run in the session sandbox; tests use the same Deno flags without systemd.

import { encodeMessage, readMessages } from '../shared/ipc.ts';
import type { ControllerToWorker } from '../shared/ipc.ts';
import type { SessionNet, SessionTarget } from './netns.ts';
import { renderSystemdRun, type SandboxLimits, unitName, workerDenoArgs } from './sandbox.ts';

export interface WorkerHandle {
  send(message: ControllerToWorker): void;
  messages: AsyncIterable<unknown>;
  kill(): Promise<void>;
  exited: Promise<number>;
}

export interface WorkerLauncher {
  launch(
    target: SessionTarget,
    net: SessionNet | null,
    limits: SandboxLimits,
  ): Promise<WorkerHandle>;
}

function wrap(child: Deno.ChildProcess, kill: () => Promise<void>): WorkerHandle {
  const writer = child.stdin.getWriter();
  const encoder = new TextEncoder();
  let chain = Promise.resolve();
  return {
    send(message) {
      const bytes = encoder.encode(encodeMessage(message));
      chain = chain.then(() => writer.write(bytes)).catch(() => {});
    },
    messages: readMessages(child.stdout),
    kill,
    exited: child.status.then((status) => status.code),
  };
}

export class SystemdLauncher implements WorkerLauncher {
  constructor(private readonly runtimeRoot: string) {}

  launch(
    target: SessionTarget,
    net: SessionNet | null,
    limits: SandboxLimits,
  ): Promise<WorkerHandle> {
    if (!net) throw new Error('A session network is required');
    const argv = renderSystemdRun(net, target, this.runtimeRoot, limits);
    const child = new Deno.Command(argv[0], {
      args: argv.slice(1),
      stdin: 'piped',
      stdout: 'piped',
      stderr: 'null',
    }).spawn();
    const unit = unitName(net);
    return Promise.resolve(wrap(child, async () => {
      await new Deno.Command('systemctl', {
        args: ['kill', '--signal=KILL', `${unit}.service`],
        stdout: 'null',
        stderr: 'null',
      })
        .output().catch(() => {});
      try {
        child.kill('SIGKILL');
      } catch { /* gone */ }
    }));
  }
}

/** Test launcher: the worker with its Deno permissions, without systemd or a namespace. */
export class DirectLauncher implements WorkerLauncher {
  constructor(
    private readonly runtimeRoot: string,
    private readonly stderr: 'inherit' | 'null' = 'null',
  ) {}

  launch(
    target: SessionTarget,
    _net: SessionNet | null,
    limits: SandboxLimits,
  ): Promise<WorkerHandle> {
    const child = new Deno.Command('deno', {
      args: workerDenoArgs(this.runtimeRoot, target, limits.memoryMaxMB),
      stdin: 'piped',
      stdout: 'piped',
      stderr: this.stderr,
      env: { NO_COLOR: '1' },
    }).spawn();
    return Promise.resolve(wrap(child, () => {
      try {
        child.kill('SIGKILL');
      } catch { /* gone */ }
      return Promise.resolve();
    }));
  }
}
