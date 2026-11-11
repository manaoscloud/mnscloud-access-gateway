// What a support level may do with each command class in manual mode (assessment 7.2).
// `unknown` is already write_risky when it reaches this table (fail-closed). Rollback automation
// (safe mode, commit confirmed) arrives with ST-F; until then a write only needs the operator's
// explicit confirmation of the reconstructed line.

import type { CommandClass } from '../shared/framing.ts';
import type { SupportLevel } from '../shared/ipc.ts';

export type Decision = 'allow' | 'confirm' | 'double_confirm' | 'block';

export const POLICY: Record<SupportLevel, Record<CommandClass, Decision>> = {
  n1: {
    read: 'allow',
    write_low: 'block',
    write_risky: 'block',
    destructive: 'block',
    pivot: 'block',
    secret_read: 'block',
  },
  n2: {
    read: 'allow',
    write_low: 'confirm',
    write_risky: 'block',
    destructive: 'block',
    pivot: 'block',
    secret_read: 'block',
  },
  n3: {
    read: 'allow',
    write_low: 'confirm',
    write_risky: 'confirm',
    destructive: 'double_confirm',
    pivot: 'confirm',
    secret_read: 'block',
  },
};

export function decide(level: SupportLevel, commandClass: CommandClass): Decision {
  return POLICY[level]?.[commandClass] ?? 'block';
}

export function blockHint(level: SupportLevel, commandClass: CommandClass, unknown: boolean) {
  if (commandClass === 'secret_read') {
    return 'Commands that show secrets are not available in the console.';
  }
  if (unknown) {
    return level === 'n3'
      ? 'Unrecognized command.'
      : 'Unrecognized commands (or lines edited with arrows, Tab or history) need support level N3.';
  }
  if (
    commandClass === 'destructive' || commandClass === 'pivot' || commandClass === 'write_risky'
  ) {
    return 'This command needs support level N3.';
  }
  return 'This command needs support level N2 or N3.';
}
