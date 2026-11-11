import type { ControlMessage } from '../src/shared/framing.ts';
import type { CommandEvent, ShellDialect, SupportLevel } from '../src/shared/ipc.ts';
import { Classifier } from '../src/worker/classifier.ts';
import { InputGate } from '../src/worker/input_gate.ts';
import { Redactor } from '../src/worker/redaction.ts';
import { loadRules } from '../src/worker/rules.ts';
import { assert, assertEquals } from './assert.ts';

function harness(dialect: ShellDialect, level: SupportLevel) {
  const rules = loadRules(dialect);
  const redactor = new Redactor(rules.redact);
  const sent: string[] = [];
  const controls: ControlMessage[] = [];
  const events: CommandEvent[] = [];
  const markers: string[] = [];
  const gate = new InputGate(new Classifier(rules), level, {
    toDevice: (d) => sent.push(d),
    control: (m) => controls.push(m),
    event: (e) => events.push(e),
    marker: (m) => markers.push(m),
    redactLine: (l) => redactor.redactText(l),
  }, 1);
  return { gate, sent, controls, events, markers, device: () => sent.join('') };
}

Deno.test('gate: read commands run at once', () => {
  const h = harness('routeros', 'n1');
  h.gate.input('/interface print\r');
  assertEquals(h.device(), '/interface print\r');
  assertEquals(h.events.map((e) => [e.class, e.verdict]), [['read', 'allowed']]);
  h.gate.close();
});

Deno.test('gate: a write waits for confirmation of the reconstructed line', () => {
  const h = harness('routeros', 'n2');
  h.gate.input('/system identity set name=X\r');
  assertEquals(h.device(), '/system identity set name=X');
  const verdict = h.controls.find((c) => c.type === 'verdict') as Extract<
    ControlMessage,
    { type: 'verdict' }
  >;
  assertEquals([verdict.class, verdict.requires, verdict.line], [
    'write_low',
    'confirm',
    '/system identity set name=X',
  ]);
  // Input typed while waiting is queued, not sent.
  h.gate.input('/interface print\r');
  assertEquals(h.device(), '/system identity set name=X');
  h.gate.decide({ type: 'confirm', id: 'wrong-id' });
  assertEquals(h.device(), '/system identity set name=X');
  h.gate.decide({ type: 'confirm', id: verdict.id });
  assertEquals(h.device(), '/system identity set name=X\r/interface print\r');
  assertEquals(h.events.map((e) => e.verdict), ['confirmed', 'allowed']);
  h.gate.close();
});

Deno.test('gate: denial clears the device line with the dialect cancel key', () => {
  const h = harness('linux', 'n3');
  h.gate.input('reboot\r');
  const verdict = h.controls.find((c) => c.type === 'verdict') as Extract<
    ControlMessage,
    { type: 'verdict' }
  >;
  h.gate.decide({ type: 'deny', id: verdict.id });
  assertEquals(h.device(), 'reboot\u0015');
  assertEquals(h.events[0].verdict, 'denied');
  h.gate.close();
});

Deno.test('gate: destructive needs two confirmations at N3 and is blocked below', () => {
  const n3 = harness('routeros', 'n3');
  n3.gate.input('/system reset-configuration\r');
  const first = n3.controls.find((c) => c.type === 'verdict') as Extract<
    ControlMessage,
    { type: 'verdict' }
  >;
  assertEquals([first.requires, first.step], ['double_confirm', 1]);
  n3.gate.decide({ type: 'confirm', id: first.id, step: 2 }); // wrong step
  n3.gate.decide({ type: 'confirm', id: first.id, step: 1 });
  assert(!n3.device().endsWith('\r'));
  n3.gate.decide({ type: 'confirm', id: first.id, step: 2 });
  assert(n3.device().endsWith('\r'));
  n3.gate.close();

  const n2 = harness('routeros', 'n2');
  n2.gate.input('/system reset-configuration\r');
  assertEquals(n2.controls.find((c) => c.type === 'blocked')?.type, 'blocked');
  assertEquals(n2.device(), '/system reset-configuration\u0003');
  n2.gate.close();
});

Deno.test('gate: secret_read is always blocked, also at N3', () => {
  const h = harness('linux', 'n3');
  h.gate.input('cat /etc/shadow\r');
  const blocked = h.controls.find((c) => c.type === 'blocked') as Extract<
    ControlMessage,
    { type: 'blocked' }
  >;
  assertEquals(blocked.class, 'secret_read');
  assert(!h.device().includes('\r'));
  h.gate.close();
});

Deno.test('gate: arrows, Tab and history taint the line (unknown -> write_risky, fail-closed)', () => {
  for (const keys of ['\x1b[A', '\t', '\x12', '\x1bOD']) {
    const h = harness('linux', 'n2');
    h.gate.input('ls' + keys + '\r');
    const blocked = h.controls.find((c) => c.type === 'blocked') as Extract<
      ControlMessage,
      { type: 'blocked' }
    >;
    assertEquals([blocked?.class, blocked?.unknown], ['write_risky', true], JSON.stringify(keys));
    h.gate.close();
  }
  const n3 = harness('linux', 'n3');
  n3.gate.input('ls\x1b[D\x1b[Drm -rf /\r');
  const verdict = n3.controls.find((c) => c.type === 'verdict') as Extract<
    ControlMessage,
    { type: 'verdict' }
  >;
  assertEquals([verdict.class, verdict.unknown], ['write_risky', true]);
  n3.gate.close();
});

Deno.test('gate: RouterOS "?" help is untrackable; Ctrl+C resets the line', () => {
  const h = harness('routeros', 'n1');
  h.gate.input('/interface ?');
  h.gate.input('\x03');
  h.gate.input('/interface print\r');
  assertEquals(h.events.map((e) => e.verdict), ['allowed']);
  h.gate.close();
});

Deno.test('gate: backspace edits the shadow buffer; split escape sequences are reassembled', () => {
  const h = harness('linux', 'n1');
  h.gate.input('rebooX\x7fx\x7f\x7f\x7f\x7f\x7f\x7fls\r');
  assertEquals(h.events[0].class, 'read');
  h.gate.input('ls\x1b');
  h.gate.input('[A\r');
  assertEquals(h.events[1].unknown, true);
  h.gate.close();
});

Deno.test('gate: a pasted block runs line by line, each classified', () => {
  const h = harness('linux', 'n2');
  h.gate.input('\x1b[200~uptime\rreboot\rdf -h\r\x1b[201~');
  assertEquals(h.events.map((e) => [e.class, e.verdict]), [['read', 'allowed'], [
    'write_risky',
    'blocked',
  ], ['read', 'allowed']]);
  assertEquals(h.device(), 'uptime\rreboot\u0015df -h\r');
  h.gate.close();
});

Deno.test('gate: verdicts expire and deny', async () => {
  const h = harness('linux', 'n3');
  h.gate.input('reboot\r');
  await new Promise((r) => setTimeout(r, 1100));
  assertEquals(h.events[0].verdict, 'expired');
  assertEquals(h.device(), 'reboot\u0015');
  h.gate.close();
});

Deno.test('gate: Ctrl+C while a verdict is open cancels it', () => {
  const h = harness('linux', 'n3');
  h.gate.input('reboot\r');
  h.gate.input('\x03');
  assertEquals(h.events[0].verdict, 'denied');
  h.gate.close();
});

Deno.test('gate: command events and markers carry the redacted line', () => {
  const h = harness('routeros', 'n2');
  h.gate.input('/user set admin password=Hunter2x\r');
  const blocked = h.controls.find((c) => c.type === 'blocked') as Extract<
    ControlMessage,
    { type: 'blocked' }
  >;
  assert(!blocked.line.includes('Hunter2x'));
  assert(!h.events[0].line.includes('Hunter2x'));
  assert(!h.markers[0].includes('Hunter2x'));
  h.gate.close();
});

Deno.test('gate: inside a full-screen program only an empty Enter passes unclassified', () => {
  const h = harness('linux', 'n1');
  h.gate.input('less /var/log/syslog\r');
  h.gate.observeOutput('\x1b[?1049h');
  h.gate.input('q');
  h.gate.observeOutput('\x1b[?1049l');
  h.gate.input('ls\r');
  assertEquals(h.events.map((e) => [e.line, e.verdict]), [['less /var/log/syslog', 'allowed'], [
    'ls',
    'allowed',
  ]]);
  h.gate.observeOutput('\x1b[?1049h');
  h.gate.input('\r');
  h.gate.input('!rm -rf /\r');
  assertEquals(h.events[2].verdict, 'blocked');
  h.gate.close();
});
