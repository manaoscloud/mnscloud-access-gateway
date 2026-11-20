// Fake SSH devices for the second-wave CLI dialects (ios, junos, fortios, vsol, dmos). They are
// protocol simulators written from the vendors' documented CLI behaviour: prompts, modes, pager,
// confirmations, `reload in`, and for Junos the NETCONF subsystem (candidate lock, load, confirmed
// commit with the nonpersistent session-close revert). They prove the gateway's protocol handling and
// its fail-closed branches; they are NOT evidence that any hardware or firmware behaves this way.

// @ts-types="../src/types/ssh2.d.ts"
import ssh2 from 'ssh2';
import { BASE, CAP, JUNOS, NC } from '../src/worker/junos/netconf.ts';
import { MON } from '../src/worker/junos/namespaces.ts';
import { escapeXml } from '../src/worker/junos/xml.ts';

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
  lockUnsupported?: boolean;
  lockOutput?: string;
  loseLockAfterStep?: boolean;
  unknownBaseline?: boolean;
  backupCollision?: boolean;
  saveReadbackMismatch?: boolean;
  cancelLostAck?: boolean;
  cancelUnknownAck?: boolean;
  saveLostAck?: boolean;
  foreignTimerAfterArm?: boolean;
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
  // --- junos (NETCONF subsystem on the authenticated SSH connection + CLI helper shells)
  /** Hello capabilities of the NETCONF server (default: everything the gateway requires). */
  netconfCapabilities?: string[];
  /** The candidate is locked by another session. */
  lockDenied?: boolean;
  /** The candidate already holds foreign uncommitted edits (the lock is refused). */
  candidateDirty?: boolean;
  /** The backup target already exists. */
  backupExists?: boolean;
  /** `show configuration | save` answers an error. */
  failBackupSave?: boolean;
  /** The confirming `<commit/>` is applied but its reply is lost (the channel closes). */
  lostConfirmReply?: boolean;
  /** A verification connection never answers `show version` (to cancel the request there). */
  hangVerify?: boolean;
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
  /** junos: content of every file saved by `show configuration | save`. */
  fileContent: Map<string, string[]>;
  /** junos: every NETCONF RPC body received, in order. */
  netconf: string[];
  netconfOpened: number;
  netconfClosed: number;
  shellsOpened: number;
  shellsClosed: number;
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
    candidate: [...base, ...(options.candidateDirty ? ['set foreign x'] : [])],
    files: [],
    fileContent: new Map(),
    netconf: [],
    netconfOpened: 0,
    netconfClosed: 0,
    shellsOpened: 0,
    shellsClosed: 0,
    reloadScheduled: options.reloadPending ?? false,
    confirmTimer: false,
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
  let reloadReason = 'foreign-maintenance';
  const savedFiles = new Map<string, string[]>();
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

    const iosLine = (input: string) => {
      const operational = mode === 'config' && input.startsWith('do ');
      const cmd = operational ? input.slice(3) : input;
      if (cmd === 'show configuration lock') {
        if (options.lockOutput) return done(options.lockOutput);
        return done(
          `Parser Configure Lock\n------------------------------------------------------------\nOwner PID : 3\nUser : support\nTTY : 1\nType : EXCLUSIVE\nState : ${
            exclusiveOwner === client ? 'LOCKED' : 'UNLOCKED'
          }\nClass : EXPOSED\nCount : 1\nPending Requests : 0`,
        );
      }
      if (cmd === 'configure terminal lock') {
        if (options.lockUnsupported || exclusiveOwner && exclusiveOwner !== client) {
          return done(IOS_ERR);
        }
        exclusiveOwner = client;
        mode = 'config';
        device.events.push('lock-acquired');
        return done(
          'Configuration mode locked exclusively. The lock will be cleared once you exit out of configuration mode using end/exit\nEnter configuration commands, one per line. End with CNTL/Z.',
        );
      }
      if (mode === 'config' && !operational) {
        if (cmd === 'end') {
          mode = 'exec';
          exclusiveOwner = null;
          return done();
        }
        if (exclusiveOwner !== client) return done('% Configuration lock lost');
        if (options.badStep && cmd.includes(options.badStep)) return done(IOS_ERR);
        if (cmd === 'no shutdown') device.running = device.running.filter((l) => l !== 'shutdown');
        else device.running.push(cmd);
        if (options.loseLockAfterStep) exclusiveOwner = null;
        return done();
      }
      if (cmd === 'terminal length 0') return done();
      if (cmd === 'show reload') {
        return done(
          device.reloadScheduled
            ? `Reload scheduled in 5 minutes by support\nReload reason: ${reloadReason}`
            : 'No reload is scheduled.',
        );
      }
      if (/^show archive config differences/.test(cmd)) {
        if (options.noDiffCommand) return done('% Archive feature is not enabled');
        if (options.unknownBaseline) return done('No changes were found\nUNKNOWN CONTEXT');
        const file = /^show archive config differences flash:(\S+)/.exec(cmd)?.[1];
        const baseline = file ? savedFiles.get(file) : device.startup;
        if (!baseline) return done('%Error missing backup');
        const d = diff(baseline, device.running);
        return done(
          d.length ? `!Contextual Config Diffs:\n${d.join('\n')}` : 'No changes were found',
        );
      }
      const directory = /^dir flash:(\S+)$/.exec(cmd);
      if (directory) {
        return done(
          options.backupCollision || savedFiles.has(directory[1])
            ? 'Directory of flash:/\n123 -rw- 1024 existing-file'
            : `%Error opening flash:${directory[1]} (No such file or directory)`,
        );
      }
      const copy = /^copy running-config flash:(\S+)$/.exec(cmd);
      if (copy) {
        if (options.failBackup) return done('%Error opening flash:' + copy[1] + ' (No space left)');
        return ask(`Destination filename [${copy[1]}]? `, (answer) => {
          device.answers.push(`dest:${answer}`);
          device.files.push(copy[1]);
          savedFiles.set(copy[1], [...device.running]);
          done('!!\n1024 bytes copied in 0.2 secs (5120 bytes/sec)');
        });
      }
      if (cmd === 'copy running-config startup-config') {
        return ask('Destination filename [startup-config]? ', (answer) => {
          device.answers.push(`dest:${answer}`);
          if (options.failSave) return done('%Error writing nvram: busy');
          device.startup = options.saveReadbackMismatch ? [...base] : [...device.running];
          device.events.push('saved');
          if (options.saveLostAck) {
            client.end();
            return;
          }
          done('Building configuration...\n[OK]');
        });
      }
      const reload = /^reload in (\d+)(?: (MNSCloud:[A-Za-z0-9-]+))?$/.exec(cmd);
      if (reload) {
        if (options.refuseReload) return done(IOS_ERR);
        const proceed = () =>
          ask(
            'Reload scheduled in ' + reload[1] + ' minutes\nProceed with reload? [confirm]',
            (a) => {
              device.answers.push(`reload:${a}`);
              device.reloadScheduled = true;
              reloadReason = options.foreignTimerAfterArm ? 'foreign-maintenance' : reload[2] ?? '';
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
        if (options.cancelLostAck) {
          client.end();
          return;
        }
        return done(
          options.cancelUnknownAck
            ? 'Unknown acknowledgement'
            : '***\n*** --- SHUTDOWN ABORTED ---\n***',
        );
      }
      if (cmd === 'configure terminal') {
        mode = 'config';
        return done('Enter configuration commands, one per line.  End with CNTL/Z.');
      }
      if (index > 0 && options.foreignAfterApply) {
        if (exclusiveOwner) device.events.push('foreign-write-refused');
        else device.running.push('ntp server 203.0.113.9');
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

    const junosLine = (cmd: string) => {
      if (cmd === 'set cli screen-length 0') return done('Screen length set to 0');
      const listed = /^file list (\/var\/tmp\/\S+)$/.exec(cmd);
      if (listed) {
        return done(
          options.backupExists || device.files.includes(listed[1])
            ? listed[1]
            : `${listed[1]}: No such file or directory`,
        );
      }
      const save = /^show configuration \| save (\/var\/tmp\/\S+)$/.exec(cmd);
      if (save) {
        if (options.failBackupSave) return done('error: cannot write ' + save[1]);
        device.files.push(save[1]);
        device.fileContent.set(save[1], [...device.committed]);
        device.events.push(`saved:${save[1].replace(/^.*-(pre|post)\.conf$/, '$1')}`);
        return done(
          `Wrote ${device.committed.length + 3} lines of configuration to '${save[1]}'`,
        );
      }
      if (index > 0 && options.failVerify?.test(cmd)) return done('unknown command.');
      if (index > 0 && options.hangVerify && cmd === 'show version') {
        hung = true;
        device.events.push('verify-hang');
        return;
      }
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

  let candidateLock: string | null = options.lockDenied ? 'foreign' : null;
  let pendingOwner: string | null = null;
  let revision = 1;
  const unescape = (text: string) =>
    text.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>').replace(/&amp;/g, '&');

  /** A scripted NETCONF server in the documented wire shapes; not captured device output. */
  // deno-lint-ignore no-explicit-any
  const netconf = (stream: any, index: number) => {
    const sessionId = String(4000 + index);
    let buffer = '';
    device.netconfOpened++;
    const send = (xml: string) => stream.write(xml + ']]>]]>');
    const reply = (id: string, body = '<ok/>') =>
      send(`<rpc-reply xmlns="${NC}" message-id="${id}">${body}</rpc-reply>`);
    const refuse = (id: string, tag: string) =>
      reply(
        id,
        `<rpc-error><error-type>protocol</error-type><error-tag>${tag}</error-tag><error-message>device detail</error-message></rpc-error>`,
      );
    const config = (lines: string[]) =>
      `<configuration xmlns:junos="http://xml.juniper.net/junos/23.4R1/junos" junos:commit-seconds="100"><interfaces><interface><name>ge-0/0/1</name><description>${
        escapeXml(lines.join('\n'))
      }</description></interface></interfaces></configuration>`;
    const capabilities = options.netconfCapabilities ??
      [BASE, CAP + 'candidate:1.0', CAP + 'confirmed-commit:1.1', CAP + 'validate:1.1', JUNOS, MON];
    stream.on('close', () => {
      device.netconfClosed++;
      if (candidateLock === sessionId) candidateLock = null;
      // Nonpersistent confirmed commit: the session that issued it ends, the device reverts.
      if (device.confirmTimer && pendingOwner === sessionId) {
        device.committed = [...junosBefore];
        device.confirmTimer = false;
        pendingOwner = null;
        revision++;
        device.events.push('session-closed-revert');
      }
    });
    const handle = (frame: string) => {
      if (frame.startsWith('<hello')) {
        send(
          `<hello xmlns="${NC}"><capabilities>${
            capabilities.map((c) => `<capability>${escapeXml(c)}</capability>`).join('')
          }</capabilities><session-id>${sessionId}</session-id></hello>`,
        );
        return;
      }
      const id = /message-id="(\d+)"/.exec(frame)![1];
      const body = frame.slice(frame.indexOf('>') + 1, frame.lastIndexOf('</rpc>'));
      device.netconf.push(body);
      if (body.startsWith('<lock>')) {
        if (candidateLock || diff(device.committed, device.candidate).length) {
          return refuse(id, 'lock-denied');
        }
        candidateLock = sessionId;
        return reply(id);
      }
      if (body.startsWith('<unlock>')) {
        if (candidateLock === sessionId) candidateLock = null;
        return reply(id);
      }
      if (body.startsWith('<get><filter')) {
        return reply(
          id,
          `<data><netconf-state xmlns="${MON}"><datastores><datastore><name>candidate</name>${
            candidateLock
              ? `<locks><locked-by-session>${candidateLock}</locked-by-session><locked-time>2026-11-19T00:00:00Z</locked-time></locks>`
              : ''
          }</datastore><datastore><name>running</name></datastore></datastores></netconf-state></data>`,
        );
      }
      if (body.startsWith('<get-commit-information')) {
        return reply(
          id,
          `<commit-information><commit-history><sequence-number>0</sequence-number><user>support</user><client>netconf</client><configuration-revision>re0-100-${revision}</configuration-revision>${
            device.confirmTimer ? '<commit-confirmed>rollback pending</commit-confirmed>' : ''
          }</commit-history></commit-information>`,
        );
      }
      if (body.startsWith('<get-configuration')) {
        return reply(
          id,
          config(body.includes('database="candidate"') ? device.candidate : device.committed),
        );
      }
      if (body.startsWith('<load-configuration')) {
        const text = /<configuration-set>([\s\S]*)<\/configuration-set>/.exec(body)![1];
        for (const line of unescape(text).split('\n')) {
          const del = /^delete (interfaces \S+) disable$/.exec(line);
          if (del) device.candidate = device.candidate.filter((l) => l !== `set ${del[1]} disable`);
          else device.candidate.push(line);
        }
        device.events.push('load');
        return reply(id, '<load-configuration-results><ok/></load-configuration-results>');
      }
      if (body.startsWith('<validate>')) return reply(id);
      if (body.startsWith('<commit><confirmed/>')) {
        junosBefore = [...device.committed];
        device.committed = [...device.candidate];
        device.confirmTimer = true;
        pendingOwner = sessionId;
        revision++;
        device.events.push('commit-confirmed');
        return reply(id);
      }
      if (body === '<commit/>') {
        device.committed = [...device.candidate];
        device.confirmTimer = false;
        pendingOwner = null;
        device.events.push('commit');
        if (options.lostConfirmReply) {
          stream.close();
          return;
        }
        return reply(id);
      }
      return refuse(id, 'operation-not-supported');
    };
    stream.on('data', (chunk: Uint8Array) => {
      buffer += new TextDecoder().decode(chunk);
      for (let at = buffer.indexOf(']]>]]>'); at >= 0; at = buffer.indexOf(']]>]]>')) {
        const frame = buffer.slice(0, at);
        buffer = buffer.slice(at + 6);
        handle(frame);
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
        session.on('shell', (ok: any) => {
          device.shellsOpened++;
          const stream = ok();
          stream.on('close', () => device.shellsClosed++);
          shell(stream, client, index);
        });
        // deno-lint-ignore no-explicit-any
        session.on('subsystem', (ok: any, reject: any, info: { name: string }) => {
          if (options.kind === 'junos' && info.name === 'netconf') netconf(ok(), index);
          else reject();
        });
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
