// Browser <-> gateway WebSocket framing (docs/runtime-api.md -> WebSocket framing).
//
// Same text frames as the VPS console of the API (termproxy style) plus two JSON channels:
//   gateway -> browser: "OK" (terminal ready), "0:<len>:<data>" (redacted device output),
//                       "3:<json>" (control: state, host key, verdict, blocked, resolved, notice)
//   browser -> gateway: "0:<len>:<data>" (keystrokes), "1:<cols>:<rows>:" (resize), "2" (ping),
//                       "4:<json>" (confirm / deny a verdict)
// Device output is ALWAYS sent as a "0:" frame, so text printed by a device can never be read
// as a control frame by the App.

export const READY_FRAME = 'OK';
export const MAX_INPUT_FRAME = 64 * 1024;
export const MAX_JSON_FRAME = 4096;

const encoder = new TextEncoder();

export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

export type CommandClass =
  | 'read'
  | 'write_low'
  | 'write_risky'
  | 'destructive'
  | 'pivot'
  | 'secret_read';

export type ControlMessage =
  | {
    type: 'state';
    state: 'connecting' | 'hostkey_check' | 'authenticating' | 'ready' | 'closed' | 'failed';
    reason?: string;
  }
  | {
    type: 'hostkey';
    kind: 'ssh' | 'tls';
    result: 'match' | 'pinned' | 'mismatch' | 'rejected';
    algorithm?: string;
    fingerprint: string;
  }
  | {
    type: 'verdict';
    id: string;
    line: string;
    class: CommandClass;
    unknown: boolean;
    requires: 'confirm' | 'double_confirm';
    step: 1 | 2;
    expiresInSeconds: number;
  }
  | {
    type: 'blocked';
    id: string;
    line: string;
    class: CommandClass;
    unknown: boolean;
    hint: string;
  }
  | { type: 'resolved'; id: string; decision: 'confirmed' | 'denied' | 'expired' }
  | { type: 'notice'; code: string; message: string };

export interface ConfirmMessage {
  type: 'confirm' | 'deny';
  id: string;
  step?: 1 | 2;
}

export type BrowserFrame =
  | { kind: 'input'; data: string }
  | { kind: 'resize'; cols: number; rows: number }
  | { kind: 'ping' }
  | { kind: 'confirm'; message: ConfirmMessage };

export function outputFrame(data: string): string {
  return `0:${utf8Length(data)}:${data}`;
}

export function controlFrame(message: ControlMessage): string {
  return `3:${JSON.stringify(message)}`;
}

/** Parses one browser frame; null for anything malformed or oversized (the frame is dropped). */
export function parseBrowserFrame(frame: string): BrowserFrame | null {
  if (typeof frame !== 'string' || frame.length > MAX_INPUT_FRAME + 16) return null;
  if (frame === '2') return { kind: 'ping' };
  if (frame.startsWith('0:')) {
    const sep = frame.indexOf(':', 2);
    if (sep < 0 || !/^\d{1,6}$/.test(frame.slice(2, sep))) return null;
    const data = frame.slice(sep + 1);
    // termproxy clients send the byte length; tolerate the UTF-16 length as well (the VPS console
    // parser ignores it), but never more data than the limit.
    const declared = Number(frame.slice(2, sep));
    if (declared !== utf8Length(data) && declared !== data.length) return null;
    return data.length > MAX_INPUT_FRAME ? null : { kind: 'input', data };
  }
  if (frame.startsWith('1:')) {
    const match = /^1:(\d{1,4}):(\d{1,4}):$/.exec(frame);
    if (!match) return null;
    const cols = Number(match[1]), rows = Number(match[2]);
    if (cols < 1 || rows < 1) return null;
    return { kind: 'resize', cols: Math.min(cols, 500), rows: Math.min(rows, 200) };
  }
  if (frame.startsWith('4:')) {
    if (frame.length > MAX_JSON_FRAME) return null;
    let value: unknown;
    try {
      value = JSON.parse(frame.slice(2));
    } catch {
      return null;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    if (record.type !== 'confirm' && record.type !== 'deny') return null;
    if (typeof record.id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(record.id)) return null;
    if (record.step !== undefined && record.step !== 1 && record.step !== 2) return null;
    const message: ConfirmMessage = { type: record.type, id: record.id };
    if (record.step !== undefined) message.step = record.step as 1 | 2;
    return { kind: 'confirm', message };
  }
  return null;
}

export type ServerFrame =
  | { kind: 'ready' }
  | { kind: 'output'; data: string }
  | { kind: 'control'; message: ControlMessage };

/** Reference parser of gateway frames (the App implements the same rules). */
export function parseServerFrame(frame: string): ServerFrame | null {
  if (frame === READY_FRAME) return { kind: 'ready' };
  if (frame.startsWith('0:')) {
    const sep = frame.indexOf(':', 2);
    if (sep < 0) return null;
    const data = frame.slice(sep + 1);
    return Number(frame.slice(2, sep)) === utf8Length(data) ? { kind: 'output', data } : null;
  }
  if (frame.startsWith('3:')) {
    try {
      return { kind: 'control', message: JSON.parse(frame.slice(2)) as ControlMessage };
    } catch {
      return null;
    }
  }
  return null;
}
