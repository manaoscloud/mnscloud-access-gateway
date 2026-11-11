// Loads the per-dialect policy data files (rules/<dialect>.json). The files are data: a rule is
// a regular expression over the normalized command line and a class; the first matching rule
// wins, and a line no rule matches is `unknown` (treated as write_risky, fail-closed).

import type { CommandClass } from '../shared/framing.ts';
import type { ShellDialect } from '../shared/ipc.ts';

export const DIALECTS: readonly ShellDialect[] = ['routeros', 'linux', 'proxmox', 'vrp', 'other'];
const CLASSES: readonly CommandClass[] = [
  'read',
  'write_low',
  'write_risky',
  'destructive',
  'pivot',
  'secret_read',
];

export type Syntax = 'routeros' | 'posix' | 'plain';

export interface Rule {
  id: string;
  class: CommandClass;
  regex: RegExp;
  hint?: string;
}

export interface RedactPattern {
  id: string;
  regex: RegExp;
}

export interface DialectRules {
  dialect: ShellDialect;
  syntax: Syntax;
  clearKeys: string[];
  untrackable: string[];
  cancelLine: string;
  navigationRoots: string[];
  rules: Rule[];
  redact: RedactPattern[];
}

interface RawRule {
  id: string;
  class: string;
  pattern: string;
  flags?: string;
  hint?: string;
}

interface RawFile {
  dialect: string;
  extends?: string;
  syntax?: string;
  flags?: string;
  clearKeys?: string[];
  untrackable?: string[];
  cancelLine?: string;
  navigationRoots?: string[];
  macros?: Record<string, string>;
  rules: RawRule[];
  redact?: { id: string; pattern: string; flags?: string }[];
}

const RULES_DIR = new URL('../../rules/', import.meta.url);

function expand(pattern: string, macros: Record<string, string>): string {
  return pattern.replace(/\{([A-Z]+)\}/g, (whole, name: string) => macros[name] ?? whole);
}

function readRaw(dialect: string): RawFile {
  if (!(DIALECTS as readonly string[]).includes(dialect)) throw new Error('Unsupported dialect');
  return JSON.parse(Deno.readTextFileSync(new URL(`${dialect}.json`, RULES_DIR))) as RawFile;
}

/** Compiles one dialect, merging the rules of the dialect it extends after its own. */
export function compileRules(raw: RawFile, base?: DialectRules): DialectRules {
  const macros = raw.macros ?? {};
  const fileFlags = raw.flags ?? '';
  const own = raw.rules.map((rule): Rule => {
    if (!(CLASSES as readonly string[]).includes(rule.class)) {
      throw new Error(`Rule ${rule.id}: unknown class ${rule.class}`);
    }
    const flags = (rule.flags ?? fileFlags).replace(/g/g, '');
    return {
      id: rule.id,
      class: rule.class as CommandClass,
      // Patterns come from the versioned rules/*.json of this repository, never from input.
      regex: new RegExp(expand(rule.pattern, macros), flags), // nosemgrep
      ...(rule.hint ? { hint: rule.hint } : {}),
    };
  });
  const redact = (raw.redact ?? []).map((pattern) => {
    const flags = pattern.flags ?? 'g';
    return {
      id: pattern.id,
      // Patterns come from the versioned rules/*.json of this repository, never from input.
      regex: new RegExp( // nosemgrep
        expand(pattern.pattern, macros),
        (flags.includes('g') ? flags : flags + 'g') + (flags.includes('d') ? '' : 'd'),
      ),
    };
  });
  return {
    dialect: raw.dialect as ShellDialect,
    syntax: (raw.syntax as Syntax | undefined) ?? base?.syntax ?? 'plain',
    clearKeys: raw.clearKeys ?? base?.clearKeys ?? [],
    untrackable: raw.untrackable ?? base?.untrackable ?? [],
    cancelLine: raw.cancelLine ?? base?.cancelLine ?? '\u0015',
    navigationRoots: raw.navigationRoots ?? base?.navigationRoots ?? [],
    rules: [...own, ...(base?.rules ?? [])],
    redact: [...redact, ...(base?.redact ?? [])],
  };
}

const cache = new Map<ShellDialect, DialectRules>();

export function loadRules(dialect: ShellDialect): DialectRules {
  const cached = cache.get(dialect);
  if (cached) return cached;
  const raw = readRaw(dialect);
  const base = raw.extends ? loadRules(raw.extends as ShellDialect) : undefined;
  const compiled = compileRules(raw, base);
  cache.set(dialect, compiled);
  return compiled;
}
