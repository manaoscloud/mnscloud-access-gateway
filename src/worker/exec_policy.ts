// Exec-mode policy on top of the console classifier. The console has a human in front of every
// line; the AI copilot does not, so a read must be provably harmless and a change must not be able
// to switch off its own rollback. All checks are deterministic string rules (fail closed).

import type { ShellDialect } from '../shared/ipc.ts';

const normalize = (command: string) => command.trim().replace(/\s+/g, ' ');

// --- reads ---------------------------------------------------------------------------------------

const ROS_VERB_END = /^\/(?:[a-z0-9-]+ )*(print|export|monitor|get|ping|traceroute)(?: [^;]*)?$/;
const ROS_SCRIPT_READ = /^:(?:put|len|typeof|tostr|tonum|toip|toarray|pick|time|resolve)\b/;

/** RouterOS exec read: full read verbs only, no navigation, no nested commands, no chaining. */
export function rosReadProblem(command: string, rule: string | null): string | null {
  const text = normalize(command);
  if (rule === 'ros-navigation') return 'navigation command';
  if (/[[;{}$]/.test(text)) return 'nested or chained command';
  if (ROS_SCRIPT_READ.test(text)) return null;
  const m = ROS_VERB_END.exec(text);
  if (!m) return 'not a full read verb';
  const verb = m[1];
  if (/\b(?:file=|follow(?:-only)?\b|interval=|as-value\b.*file)/.test(text)) {
    return 'writes a file or never ends';
  }
  if (verb === 'monitor' && !/(?:^| )(?:once|duration=\S+)(?: |$)/.test(text)) {
    return 'monitor without once/duration';
  }
  if (verb === 'ping' && !/(?:^| )count=\d+/.test(text)) return 'ping without count';
  return null;
}

const SECRET_PATH =
  /(?:^|[/\s'"=])(?:g?shadow-?|id_\w+|ssh_host_\w+_key|[^\s/'"]*\.key|private[^\s/'"]*)(?=$|[\s/'"])/;
const FLAG_BLOCKS: Record<string, RegExp> = {
  sort: /^(?:-[A-Za-z]*o|--output)/,
  tree: /^-[A-Za-z]*o/,
  xxd: /^(?:-[A-Za-z]*r|--revert)/,
  sar: /^-[A-Za-z]*o/,
  dmesg: /^(?:-[A-Za-z]*[cC]|--clear|--read-clear)/,
  ss: /^(?:-[A-Za-z]*K|--kill)/,
  man: /^(?:-P|-H|--pager|--html)/,
  yq: /^(?:-[A-Za-z]*i|--inplace)/,
  arping: /^-[A-Za-z]*[UA]/,
  ping: /^-[A-Za-z]*f/,
};
const CTL_PROGRAMS = new Set(['localectl', 'loginctl', 'resolvectl', 'timedatectl', 'hostnamectl']);

/** Linux/Proxmox exec read: no expansion, no secret paths, no flags that write or act. */
export function linuxReadProblem(command: string): string | null {
  if (/[*?[\]{}~]/.test(command)) return 'glob or expansion character';
  if (SECRET_PATH.test(command)) return 'secret path';
  for (const segment of command.split(/\|\||&&|[|;&\n]/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    while (words[0] === 'sudo' || words[0] === 'env' || words[0] === 'command') words.shift();
    const program = (words[0] ?? '').replace(/^.*\//, '');
    if (program === 'cd') return 'cd';
    const args = words.slice(1);
    const flag = FLAG_BLOCKS[program];
    if (flag && args.some((a) => flag.test(a))) return `${program} flag`;
    if (program === 'uniq' && args.filter((a) => !a.startsWith('-')).length >= 2) {
      return 'uniq output file';
    }
    if (CTL_PROGRAMS.has(program)) {
      const verb = args.find((a) => !a.startsWith('-'));
      if (verb && !/^(?:status|list.*|show.*)$/.test(verb)) return `${program} ${verb}`;
    }
  }
  return null;
}

/** VRP exec read: display, ping and tracert only; no redirection. */
export function vrpReadProblem(command: string): string | null {
  const text = normalize(command);
  if (!/^(?:dis(?:p|pl|pla|play)?|ping|tracert)\b/i.test(text)) return 'not a display command';
  if (/>|\bredirect\b|\btee\b/i.test(text)) return 'redirection';
  return null;
}

export function readProblem(
  dialect: ShellDialect,
  command: string,
  rule: string | null,
): string | null {
  if (dialect === 'routeros') return rosReadProblem(command, rule);
  if (dialect === 'linux' || dialect === 'proxmox') return linuxReadProblem(command);
  if (dialect === 'vrp') return vrpReadProblem(command);
  return 'dialect not supported';
}

// --- changes: no command may disarm its own rollback --------------------------------------------

/** True when an AI step or rollback command could switch off or outlive the vendor rollback. */
export function disarmsRollback(dialect: ShellDialect, command: string, rule: string | null) {
  const text = normalize(command);
  if (dialect === 'vrp') {
    return /^(?:sa|sav|save|undo\s+sch\w*|sch\w*|schedule|startup|commit|reboot|quit)\b/i.test(
      text,
    );
  }
  if (dialect === 'routeros') {
    if (rule === 'ros-script-exec') return true;
    // Only absolute commands: a relative one depends on a menu the policy cannot see.
    if (!text.startsWith('/') && !text.startsWith(':')) return true;
    const spaced = text.replace(/\//g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
    if (/:execute/i.test(text) || /(?:^| )(?:import|quit)(?: |$)/.test(spaced)) return true;
    // RouterOS accepts any unambiguous prefix of a word (`/sys sched`, `/system script ru`).
    const [a = '', b = '', c = ''] = spaced.split(' ');
    const abbr = (word: string, full: string) => word.length >= 2 && full.startsWith(word);
    if (abbr(a, 'system')) {
      if (abbr(b, 'scheduler') || abbr(b, 'reboot') || abbr(b, 'shutdown')) return true;
      if (abbr(b, 'script') && (c === '' || abbr(c, 'run'))) return true;
    }
    return abbr(a, 'tool') && abbr(b, 'netwatch');
  }
  if (/mns-rb-/.test(text)) return true;
  if (/\bsystemctl\b.*\b(?:stop|disable|mask|kill)\b.*(?:\.timer\b|timers\.target)/.test(text)) {
    return true;
  }
  if (/\b(?:systemd-run|at|batch|nohup|setsid|disown|crontab)\b/.test(text)) return true;
  if (/&\s*$/.test(text)) return true;
  return /\b(?:reboot|shutdown|poweroff|halt)\b/.test(text);
}

/** Time left before the rollback timer must not be relied on any more (30 s safety margin). */
export function deadlineExceeded(
  armedAt: number,
  now: number,
  rollbackSeconds: number,
  marginMs = 30000,
): boolean {
  return now - armedAt >= rollbackSeconds * 1000 - marginMs;
}
