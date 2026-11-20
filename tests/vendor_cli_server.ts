// Fake SSH devices for the second-wave CLI dialects (ios, junos, fortios, vsol, dmos). They are
// protocol simulators written from the vendors' documented CLI behaviour: prompts, modes, pager,
// confirmations, `reload in`, `commit confirmed`. They prove the gateway's protocol handling and
// its fail-closed branches; they are NOT evidence that any hardware or firmware behaves this way.

// @ts-types="../src/types/ssh2.d.ts"
import ssh2 from 'ssh2';

// deno-lint-ignore no-explicit-any
const { Server } = ssh2 as any;

export const CLI_PASSWORD = 'Dev1ce-Pa55word!';

export interface CliDeviceOptions {
  kind: 'ios' | 'junos' | 'fortios' | 'vsol' | 'dmos';
  /** Commands (regexp) that answer with the vendor error in a verification (2nd+) connection. */
  failVerify?: RegExp;
  /** A command (regexp) that asks an unexpected confirmation. */
  confirmOn?: RegExp;
  /** A command (regexp) that never returns to the prompt. */
  hang?: RegExp;
  /** Long outputs are paged with --More--. */
  pager?: boolean;
  /** Text added to `show version` (to prove redaction). */
  banner?: string;
  // --- ios
  userMode?: boolean;
  dirtyBaseline?: boolean;
  reloadPending?: boolean;
  failBackup?: boolean;
  failSave?: boolean;
  refuseReload?: boolean;
  noDiffCommand?: boolean;
  foreignAfterApply?: boolean;
  cancelFails?: boolean;
  /** The first config line that contains this text is refused. */
  badStep?: string;
  /** The connection drops when this command (regexp) is received. */
  dropOn?: RegExp;
  // --- junos
  locked?: boolean;
  candidateDirty?: boolean;
  confirmedPending?: boolean;
  failCommitCheck?: boolean;
  failCommitConfirmed?: boolean;
  failConfirm?: boolean;
  failBackupJunos?: boolean;
  failRollback1?: boolean;
}

export interface CliDevice {
  port: number;
  /** Every line typed, as `connection index:line`. */
  lines: string[];
  /** Raw answers to confirmation prompts. */
  answers: string[];
  connections: number;
  logins: { username: string; ok: boolean }[];
  running: string[];
  startup: string[];
  committed: string[];
  candidate: string[];
  files: string[];
  reloadScheduled: boolean;
  confirmTimer: boolean;
  events: string[];
  /** ios: the scheduled reload fires; junos: the confirmed-commit timer fires. */
  fire(): void;
  close(): Promise<void>;
}

const IOS_ERR = "% Invalid input detected at '^' marker.";

export function startCliDevice(hostKey: string, options: CliDeviceOptions): Promise<CliDevice> {
  const base = options.kind === 'junos' ? ['set interfaces ge-0/0/1 description old'] : [
    'interface GigabitEthernet0/1',
    'description old',
    'shutdown',
  ];
  const device: CliDevice = {
    port: 0,
    lines: [],
    answers: [],
    connections: 0,
    logins: [],
    running: [...base, ...(options.dirtyBaseline ? ['ntp server 192.0.2.7'] : [])],
    startup: [...base],
    committed: [...base],
    candidate: [],
    files: [],
    reloadScheduled: options.reloadPending ?? false,
    confirmTimer: options.confirmedPending ?? false,
    events: [],
    fire: () => {
      if (options.kind === 'junos') {
        if (device.confirmTimer) {
          device.committed = [...junosBefore];
          device.confirmTimer = false;
          device.events.push('timer-fired');
        }
      } else if (device.reloadScheduled) {
        device.running = [...device.startup];
        device.reloadScheduled = false;
        device.events.push('reloaded');
      }
    },
    close: () => Promise.resolve(),
  };
  let junosBefore = [...base];
  let exclusiveOwner: unknown = null;
  const diff = (from: string[], to: string[]) => [
    ...to.filter((l) => !from.includes(l)).map((l) => `+${l}`),
    ...from.filter((l) => !to.includes(l)).map((l) => `-${l}`),
  ];

  // deno-lint-ignore no-explicit-any
  const shell = (stream: any, client: any, index: number) => {
    const kind = options.kind;
    let mode: 'exec' | 'config' = 'exec';
    let pending: ((answer: string) => void) | null = null;
    let pagerWait: (() => void) | null = null;
    let hung = false;
    let line = '';
    const name =
      { ios: 'Router', junos: 'support@fw', fortios: 'FGT60F', vsol: 'OLT', dmos: 'DM4610' }[
        kind
      ];
    const prompt = () => {
      if (kind === 'ios') {
        return `${name}${mode === 'config' ? '(config)' : ''}${
          options.userMode && mode === 'exec' ? '>' : '#'
        } `;
      }
      if (kind === 'junos') return mode === 'config' ? `[edit]\r\n${name}# ` : `${name}> `;
      if (kind === 'fortios') return `${name} # `;
      return `${name}# `;
    };
    const say = (text: string) => stream.write(text.replace(/\n/g, '\r\n'));
    const done = (text = '') => say((text ? text + '\n' : '') + prompt());
    const error = () =>
      kind === 'junos'
        ? '                    ^\nsyntax error.'
        : kind === 'fortios'
        ? 'Unknown action 0\nCommand fail. Return code 1'
        : IOS_ERR;
    const ask = (question: string, then: (answer: string) => void) => {
      say(question);
      pending = then;
    };
    client.on('close', () => {
      if (exclusiveOwner === client) exclusiveOwner = null;
    });

    const iosLine = (cmd: string) => {
      if (mode === 'config') {
        if (cmd === 'end') {
          mode = 'exec';
          if (options.foreignAfterApply) device.running.push('ntp server 203.0.113.9');
          return done();
        }
        if (options.badStep && cmd.includes(options.badStep)) return done(IOS_ERR);
        if (cmd === 'no shutdown') device.running = device.running.filter((l) => l !== 'shutdown');
        else device.running.push(cmd);
        return done();
      }
      if (cmd === 'terminal length 0') return done();
      if (cmd === 'show reload') {
        return done(
          device.reloadScheduled
            ? 'Reload scheduled in 5 minutes by support'
            : 'No reload is scheduled.',
        );
      }
      if (/^show archive config differences/.test(cmd)) {
        if (options.noDiffCommand) return done('% Archive feature is not enabled');
        const d = diff(device.startup, device.running);
        return done(
          d.length ? `!Contextual Config Diffs:\n${d.join('\n')}` : 'No changes were found',
        );
      }
      const copy = /^copy running-config flash:(\S+)$/.exec(cmd);
      if (copy) {
        if (options.failBackup) return done('%Error opening flash:' + copy[1] + ' (No space left)');
        return ask(`Destination filename [${copy[1]}]? `, (answer) => {
          device.answers.push(`dest:${answer}`);
          device.files.push(copy[1]);
          done('!!\n1024 bytes copied in 0.2 secs (5120 bytes/sec)');
        });
      }
      if (cmd === 'copy running-config startup-config') {
        return ask('Destination filename [startup-config]? ', (answer) => {
          device.answers.push(`dest:${answer}`);
          if (options.failSave) return done('%Error writing nvram: busy');
          device.startup = [...device.running];
          device.events.push('saved');
          done('Building configuration...\n[OK]');
        });
      }
      const reload = /^reload in (\d+)$/.exec(cmd);
      if (reload) {
        if (options.refuseReload) return done(IOS_ERR);
        const proceed = () =>
          ask(
            'Reload scheduled in ' + reload[1] + ' minutes\nProceed with reload? [confirm]',
            (a) => {
              device.answers.push(`reload:${a}`);
              device.reloadScheduled = true;
              device.events.push('reload-armed');
              done();
            },
          );
        if (diff(device.startup, device.running).length) {
          return ask('System configuration has been modified. Save? [yes/no]: ', (a) => {
            device.answers.push(`save:${a}`);
            if (a === 'yes') device.startup = [...device.running];
            proceed();
          });
        }
        return proceed();
      }
      if (cmd === 'reload cancel') {
        if (!options.cancelFails) {
          device.reloadScheduled = false;
          device.events.push('reload-cancelled');
        }
        return done('***\n*** --- SHUTDOWN ABORTED ---\n***');
      }
      if (cmd === 'configure terminal') {
        mode = 'config';
        return done('Enter configuration commands, one per line.  End with CNTL/Z.');
      }
      if (index > 0 && options.failVerify?.test(cmd)) return done(IOS_ERR);
      if (cmd === 'show version') {
        return done(
          `Cisco IOS XE Software, Version 17.03.04\nuptime is 2 weeks${options.banner ?? ''}`,
        );
      }
      if (cmd === 'show interfaces' && options.pager) {
        say('GigabitEthernet0/1 is up\n --More-- ');
        pagerWait = () => done('\rGigabitEthernet0/2 is down');
        return;
      }
      if (/^show (?:ip interface brief|interfaces|clock|inventory)/.test(cmd)) {
        return done('GigabitEthernet0/1  192.0.2.2  YES  up  up');
      }
      if (cmd === 'show running-config') return done('enable secret 9 $9$LEAK');
      return done(IOS_ERR);
    };

    const commitHistory = () =>
      done(
        '0   2026-11-19 10:00:00 UTC by support via cli' +
          (device.confirmTimer ? ' commit confirmed, rollback in 5mins' : '') +
          '\n1   2026-11-18 10:00:00 UTC by root via cli',
      );

    const junosLine = (cmd: string) => {
      if (cmd === 'set cli screen-length 0') return done('Screen length set to 0');
      if (mode === 'config') {
        if (cmd === 'show | compare') {
          const d = diff(device.committed, device.candidate);
          return done(
            d.length ? '[edit]\n' + d.map((l) => l[0] + '  ' + l.slice(1)).join('\n') : '',
          );
        }
        const save = /^save (\S+)$/.exec(cmd);
        if (save) {
          if (options.failBackupJunos) return done('error: cannot write ' + save[1]);
          device.files.push(save[1]);
          return done(
            `Wrote ${device.candidate.length + 3} lines of configuration to '${save[1]}'`,
          );
        }
        if (cmd === 'commit check') {
          return done(
            options.failCommitCheck
              ? 'error: configuration check-out failed'
              : 'configuration check succeeds',
          );
        }
        const confirmed = /^commit confirmed (\d+)$/.exec(cmd);
        if (confirmed) {
          if (options.failCommitConfirmed) return done('error: commit failed');
          junosBefore = [...device.committed];
          device.committed = [...device.candidate];
          device.confirmTimer = true;
          device.events.push('commit-confirmed');
          return done(
            `commit confirmed will be automatically rolled back in ${
              confirmed[1]
            } minutes unless confirmed\ncommit complete`,
          );
        }
        if (cmd === 'commit') {
          if (options.failConfirm) return done('error: commit failed');
          device.committed = [...device.candidate];
          device.confirmTimer = false;
          device.events.push('commit');
          return done('commit complete');
        }
        if (cmd === 'rollback 0') {
          device.candidate = [...device.committed];
          return done('load complete');
        }
        if (cmd === 'rollback 1') {
          if (options.failRollback1) return done('error: rollback failed');
          device.candidate = [...junosBefore];
          return done('load complete');
        }
        if (cmd === 'exit configuration-mode') {
          if (diff(device.committed, device.candidate).length) {
            return ask('Exit with uncommitted changes? [yes,no] (yes) ', (a) => {
              device.answers.push(`exit:${a}`);
              if (a === 'yes') {
                mode = 'exec';
                exclusiveOwner = null;
                done('Exiting configuration mode');
              } else done();
            });
          }
          mode = 'exec';
          exclusiveOwner = null;
          return done('Exiting configuration mode');
        }
        if (cmd === 'run show system commit') return commitHistory();
        if (options.badStep && cmd.includes(options.badStep)) return done(error());
        const del = /^delete (interfaces \S+) disable$/.exec(cmd);
        if (del) {
          device.candidate = device.candidate.filter((l) => l !== `set ${del[1]} disable`);
          return done();
        }
        if (/^set /.test(cmd)) {
          device.candidate.push(cmd);
          return done();
        }
        return done(error());
      }
      if (cmd === 'show system commit') return commitHistory();
      if (cmd === 'configure exclusive') {
        if (options.locked) {
          return done('error: configuration database locked by:\n  other terminal p0');
        }
        exclusiveOwner = client;
        mode = 'config';
        device.candidate = [
          ...device.committed,
          ...(options.candidateDirty ? ['set foreign x'] : []),
        ];
        return done('Entering configuration mode');
      }
      if (index > 0 && options.failVerify?.test(cmd)) return done('unknown command.');
      if (cmd === 'show version') return done(`Hostname: fw\nJunos: 21.4R3${options.banner ?? ''}`);
      if (/^show (?:system uptime|interfaces terse|chassis alarms)/.test(cmd)) {
        return done('ge-0/0/1 up up');
      }
      return done('unknown command.');
    };

    const genericLine = (cmd: string) => {
      if (options.failVerify?.test(cmd) && index > 0) return done(error());
      if (/^(?:get system status|show version|show clock|show system)$/.test(cmd)) {
        return done(`Version: ${kind} 1.0.0 build 42${options.banner ?? ''}`);
      }
      if (cmd === 'get system performance status' && options.pager) {
        say('CPU states: 1%\n--More-- ');
        pagerWait = () => done('\rMemory: 40%');
        return;
      }
      if (cmd === 'get system performance status') return done('CPU states: 1%\nMemory: 40%');
      return done(error());
    };

    stream.write(`Welcome\r\n${prompt()}`);
    stream.on('data', (chunk: Uint8Array) => {
      for (const ch of new TextDecoder().decode(chunk)) {
        if (hung) continue;
        if (pagerWait) {
          if (ch === ' ') {
            const next = pagerWait;
            pagerWait = null;
            next();
          } else if (ch === 'q') {
            pagerWait = null;
            done();
          }
          continue;
        }
        if (ch === '\r') {
          const typed = line;
          line = '';
          stream.write('\r\n');
          if (pending) {
            const next = pending;
            pending = null;
            next(typed);
            continue;
          }
          device.lines.push(`${index}:${typed}`);
          if (options.dropOn?.test(typed)) {
            client.end();
            return;
          }
          if (options.hang?.test(typed)) {
            hung = true;
            continue;
          }
          if (options.confirmOn?.test(typed)) {
            ask('Do you want to continue? (y/n) ', (a) => {
              device.answers.push(`unexpected:${a}`);
              done(a === 'y' || a === 'yes' ? 'done' : 'aborted');
            });
            continue;
          }
          if (kind === 'ios') iosLine(typed);
          else if (kind === 'junos') junosLine(typed);
          else genericLine(typed);
        } else if (ch >= ' ' && ch !== '\x7f') {
          line += ch;
          stream.write(ch);
        }
      }
    });
  };

  // deno-lint-ignore no-explicit-any
  const server = new Server({ hostKeys: [hostKey] }, (client: any) => {
    // deno-lint-ignore no-explicit-any
    client.on('authentication', (ctx: any) => {
      const ok = ctx.method === 'password' && ctx.username === 'support' &&
        ctx.password === CLI_PASSWORD;
      device.logins.push({ username: ctx.username, ok });
      if (ok) ctx.accept();
      else ctx.reject(['password']);
    });
    client.on('error', () => {});
    client.on('ready', () => {
      const index = device.connections++;
      // deno-lint-ignore no-explicit-any
      client.on('session', (accept: any) => {
        const session = accept();
        // deno-lint-ignore no-explicit-any
        session.on('pty', (ok: any) => ok());
        // deno-lint-ignore no-explicit-any
        session.on('shell', (ok: any) => shell(ok(), client, index));
      });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      device.port = server.address().port;
      device.close = () => new Promise<void>((r) => server.close(() => r()));
      resolve(device);
    });
  });
}
