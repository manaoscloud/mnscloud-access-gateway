// Deterministic command classifier (assessment 7.2). It classifies the line the operator really
// typed (reconstructed by the input gate), never a declared intention. Anything it cannot
// recognize is `unknown`, which the policy treats as write_risky (fail-closed).

import type { CommandClass } from '../shared/framing.ts';
import type { DialectRules, Rule } from './rules.ts';

export const SEVERITY: Record<CommandClass, number> = {
  read: 0,
  write_low: 1,
  write_risky: 2,
  pivot: 3,
  destructive: 4,
  secret_read: 5,
};

export interface Classification {
  class: CommandClass;
  unknown: boolean;
  rule: string | null;
  hint?: string;
  normalized: string;
}

function strictest(a: Classification, b: Classification): Classification {
  if (SEVERITY[b.class] > SEVERITY[a.class]) return b;
  if (SEVERITY[b.class] === SEVERITY[a.class] && b.unknown && !a.unknown) return b;
  return a;
}

function match(rules: Rule[], text: string): Classification {
  for (const rule of rules) {
    if (rule.regex.test(text)) {
      return {
        class: rule.class,
        unknown: false,
        rule: rule.id,
        normalized: text,
        ...(rule.hint ? { hint: rule.hint } : {}),
      };
    }
  }
  return { class: 'write_risky', unknown: true, rule: null, normalized: text };
}

const UNKNOWN = (text: string, rule: string): Classification => ({
  class: 'write_risky',
  unknown: true,
  rule,
  normalized: text,
});

// ---------------------------------------------------------------------------------------------
// POSIX shells
// ---------------------------------------------------------------------------------------------

interface PosixSplit {
  segments: string[];
  substitutions: string[];
  opaque: boolean; // command substitution, process substitution, heredoc
  continuation: boolean; // trailing backslash or unbalanced quotes
  redirects: string[];
}

export function splitPosix(line: string): PosixSplit {
  const segments: string[] = [];
  const redirects: string[] = [];
  const substitutions = innerSubstitutions(line);
  let current = '';
  let quote: '"' | "'" | null = null;
  let opaque = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (quote === "'") {
      if (ch === "'") quote = null;
      current += ch;
      continue;
    }
    if (ch === '\\') {
      if (i === line.length - 1) {
        return { segments, substitutions, opaque, continuation: true, redirects };
      }
      current += ch + next;
      i++;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === '`' || (ch === '$' && next === '(')) opaque = true;
      current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (
      ch === '`' || (ch === '$' && next === '(') || ((ch === '<' || ch === '>') && next === '(')
    ) {
      opaque = true;
    }
    if (ch === '<' && next === '<') opaque = true;
    if (ch === ';' || ch === '|' || ch === '&' || ch === '\n') {
      // "2>&1" / ">&2" are redirections, not separators.
      if (ch === '&' && (current.endsWith('>') || next === '>')) {
        current += ch;
        continue;
      }
      segments.push(current);
      current = '';
      if ((ch === '|' || ch === '&') && next === ch) i++;
      continue;
    }
    if (ch === '>') {
      let j = i + 1;
      if (line[j] === '>' || line[j] === '|') j++;
      while (line[j] === ' ') j++;
      let target = '';
      while (j < line.length && !/[\s;|&<>]/.test(line[j])) target += line[j++];
      redirects.push(target);
    }
    current += ch;
  }
  segments.push(current);
  return { segments, substitutions, opaque, continuation: quote !== null, redirects };
}

/** Text inside $( ... ), <( ... ), >( ... ) and backticks (outside single quotes). */
export function innerSubstitutions(line: string): string[] {
  const out: string[] = [];
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      continue;
    }
    if (ch === '\\') {
      i++;
      continue;
    }
    if (ch === "'" && quote === null) {
      quote = "'";
      continue;
    }
    if (ch === '"') {
      quote = quote === '"' ? null : '"';
      continue;
    }
    if (ch === '`') {
      const end = line.indexOf('`', i + 1);
      out.push(line.slice(i + 1, end < 0 ? line.length : end));
      i = end < 0 ? line.length : end;
      continue;
    }
    if ((ch === '$' || ch === '<' || ch === '>') && line[i + 1] === '(') {
      let depth = 0, j = i + 1;
      for (; j < line.length; j++) {
        if (line[j] === '(') depth++;
        else if (line[j] === ')' && --depth === 0) break;
      }
      out.push(line.slice(i + 2, j));
      i = j;
    }
  }
  return out;
}

const SUDO_OPTION_WITH_VALUE = new Set(['-u', '-g', '-C', '-h', '-p', '-r', '-t', '-U', '-T']);
const SUDO_SHELL_OPTIONS = /^-(?:[a-zA-Z]*[isel][a-zA-Z]*|-login|-shell|-edit|-list)$/;

/** Removes wrappers that only run the next command (sudo, time, nice, watch, ...). */
export function unwrapPosix(segment: string): string {
  let words = segment.trim().split(/\s+/).filter(Boolean);
  for (let guard = 0; guard < 8 && words.length; guard++) {
    // Leading environment assignments: "LANG=C ls".
    let k = 0;
    while (k < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k])) k++;
    if (k > 0 && k < words.length) {
      words = words.slice(k);
      continue;
    }
    const head = words[0].replace(/^.*\//, '');
    if (head === 'sudo' || head === 'doas') {
      let j = 1;
      while (j < words.length && words[j].startsWith('-')) {
        if (SUDO_SHELL_OPTIONS.test(words[j])) return words.join(' ');
        j += SUDO_OPTION_WITH_VALUE.has(words[j]) ? 2 : 1;
      }
      if (j >= words.length || words[j] === 'su') return words.join(' ');
      words = words.slice(j);
      continue;
    }
    if (
      ['time', 'nice', 'nohup', 'command', 'builtin', 'stdbuf', 'ionice', 'chrt'].includes(head)
    ) {
      let j = 1;
      while (j < words.length && words[j].startsWith('-')) {
        j += /^-[nc]$/.test(words[j]) && head !== 'command' ? 2 : 1;
      }
      if (j >= words.length) return words.join(' ');
      words = words.slice(j);
      continue;
    }
    if (head === 'watch' || head === 'timeout') {
      let j = 1;
      while (j < words.length && words[j].startsWith('-')) {
        j += /^-(?:n|d|s|k|-interval|-signal)$/.test(words[j]) ? 2 : 1;
      }
      if (head === 'timeout' && j < words.length && /^\d/.test(words[j])) j++;
      if (j >= words.length) return words.join(' ');
      words = words.slice(j);
      continue;
    }
    if (head === 'xargs') {
      let j = 1;
      while (j < words.length && words[j].startsWith('-')) {
        j += /^-[IinLPsdE]$/.test(words[j]) ? 2 : 1;
      }
      if (j >= words.length) return words.join(' ');
      words = words.slice(j);
      continue;
    }
    break;
  }
  if (words.length) words[0] = words[0].replace(/^.*\/(?=[^/]+$)/, '');
  return words.join(' ');
}

const SAFE_REDIRECT = /^(?:&?[0-9]?|\/dev\/(?:null|stdout|stderr|tty))$/;
const SYSTEM_TARGET = /^\/(?:boot|etc|usr|bin|sbin|lib|lib64|root|dev\/|proc\/|sys\/)/;

function classifyPosix(rules: DialectRules, line: string, depth = 0): Classification {
  const split = splitPosix(line);
  let result: Classification | null = null;
  for (const segment of split.segments) {
    const segmentResult = match(rules.rules, unwrapPosix(segment));
    result = result ? strictest(result, segmentResult) : segmentResult;
  }
  result ??= match(rules.rules, '');
  for (const inner of split.substitutions) {
    result = strictest(
      result,
      depth < 3 ? classifyPosix(rules, inner, depth + 1) : UNKNOWN(inner, 'sh-substitution'),
    );
  }
  for (const target of split.redirects) {
    if (SAFE_REDIRECT.test(target)) continue;
    result = strictest(result, {
      class: SYSTEM_TARGET.test(target) ? 'write_risky' : 'write_low',
      unknown: false,
      rule: 'sh-redirect',
      normalized: line,
    });
  }
  if (split.opaque) result = strictest(result, UNKNOWN(line, 'sh-substitution'));
  if (split.continuation) result = strictest(result, UNKNOWN(line, 'sh-continuation'));
  return { ...result, normalized: line.trim() };
}

// ---------------------------------------------------------------------------------------------
// RouterOS
// ---------------------------------------------------------------------------------------------

const NAVIGATION_TOKEN = /^[a-z0-9][a-z0-9-]*$/;
// A token that may be a command rather than a menu; such a line is never treated as navigation.
const VERB_FRAGMENT =
  /(?:^|-)(?:reset|remove|delete|format|upgrade|install|reboot|shutdown|run|import|send|fetch|save|load|set|add|enable|disable|clear|flush|release|renew|unset|apply|sign|cancel|start|stop|make|uninstall|downgrade|update|erase|wipe|kill|test|scan|exec|execute|move|edit|comment|monitor|print|export|get|find|ping|traceroute|torch|quit|check|generate|create|backup|restore|reload|regenerate|accept|connect|disconnect|activate)(?:$|-)/;

/** Splits on top-level ";" (outside quotes, brackets and braces). */
export function splitRouterOs(line: string): string[] {
  const out: string[] = [];
  let current = '', quote = false, depth = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') {
        current += ch + (line[i + 1] ?? '');
        i++;
        continue;
      }
      if (ch === '"') quote = false;
      current += ch;
      continue;
    }
    if (ch === '"') quote = true;
    if (ch === '[' || ch === '{') depth++;
    if ((ch === ']' || ch === '}') && depth > 0) depth--;
    if (ch === ';' && depth === 0) {
      out.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

/** Inner commands of "[ ... ]" substitutions (one level). */
export function bracketCommands(line: string): string[] {
  const out: string[] = [];
  let depth = 0, start = -1, quote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== '\\') quote = !quote;
    if (quote) continue;
    if (ch === '[') {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === ']' && depth > 0) {
      depth--;
      if (depth === 0 && start >= 0) out.push(line.slice(start, i));
    }
  }
  return out;
}

/** "/ip/firewall/filter/add chain=input" -> "/ip firewall filter add chain=input". */
export function normalizeRouterOs(text: string): string {
  const trimmed = text.trim().replace(/\s+/g, ' ');
  if (!trimmed || trimmed.startsWith(':')) return trimmed;
  const words = trimmed.split(' ');
  let i = 0;
  while (i < words.length && !/[="[\]{}]/.test(words[i])) i++;
  const headWords = words.slice(0, i).join(' ');
  const head = (headWords.startsWith('/') ? '/' : '') +
    headWords.split(/[\s/]+/).filter(Boolean).join(' ');
  return [head, ...words.slice(i)].filter(Boolean).join(' ');
}

function resolveMenu(menu: string, normalized: string): string {
  if (normalized.startsWith('/') || normalized.startsWith(':')) return normalized;
  const parts = menu ? menu.slice(1).split(' ').filter(Boolean) : [];
  const words = normalized.split(' ');
  while (words[0] === '..') {
    parts.pop();
    words.shift();
  }
  return `/${[...parts, ...words].join(' ')}`.replace(/^\/$/, '/');
}

/** A known menu path without a command ("/ip firewall filter"); anything else is a command. */
function isNavigation(full: string, roots: string[]): boolean {
  if (full === '/' || full === '/..') return true;
  if (!full.startsWith('/')) return false;
  const tokens = full.slice(1).split(' ');
  return roots.includes(tokens[0]) && tokens.length <= 5 &&
    tokens.every((t) => NAVIGATION_TOKEN.test(t) && !VERB_FRAGMENT.test(t));
}

export interface ClassifyState {
  menu: string;
}

function classifyRouterOs(
  rules: DialectRules,
  line: string,
  state: ClassifyState,
): { result: Classification; menu: string } {
  let menu = state.menu;
  let result: Classification | null = null;
  for (const segment of splitRouterOs(line)) {
    const normalized = normalizeRouterOs(segment);
    if (!normalized) continue;
    const full = resolveMenu(menu, normalized);
    let segmentResult = match(rules.rules, full);
    if (segmentResult.unknown && isNavigation(full, rules.navigationRoots)) {
      segmentResult = { class: 'read', unknown: false, rule: 'ros-navigation', normalized: full };
      menu = full === '/' ? '' : full;
    }
    for (const inner of bracketCommands(segment)) {
      const innerFull = resolveMenu(menu, normalizeRouterOs(inner));
      segmentResult = strictest(segmentResult, match(rules.rules, innerFull));
    }
    result = result ? strictest(result, segmentResult) : segmentResult;
  }
  result ??= match(rules.rules, '/');
  return { result: { ...result, normalized: line.trim() }, menu };
}

// ---------------------------------------------------------------------------------------------

/** Stateful classifier of one terminal (RouterOS keeps the current menu between lines). */
export class Classifier {
  #menu = '';
  constructor(readonly rules: DialectRules) {}

  get menu() {
    return this.#menu;
  }

  /** Classifies without changing state; `commit` applies a line that actually ran. */
  classify(line: string): Classification & { menu: string } {
    if (this.rules.syntax === 'routeros') {
      const { result, menu } = classifyRouterOs(this.rules, line, { menu: this.#menu });
      return { ...result, menu };
    }
    const text = line.trim().replace(/\s+/g, ' ');
    if (this.rules.syntax === 'posix') return { ...classifyPosix(this.rules, text), menu: '' };
    return { ...match(this.rules.rules, text), menu: '' };
  }

  commit(classification: { menu: string }) {
    if (this.rules.syntax === 'routeros') this.#menu = classification.menu;
  }

  reset() {
    this.#menu = '';
  }
}
