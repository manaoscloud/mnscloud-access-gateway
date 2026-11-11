import {
  controlFrame,
  outputFrame,
  parseBrowserFrame,
  parseServerFrame,
} from '../src/shared/framing.ts';
import { assertEquals } from './assert.ts';

Deno.test('framing: browser frames (VPS console format + confirm)', () => {
  assertEquals(parseBrowserFrame('0:3:abc'), { kind: 'input', data: 'abc' });
  assertEquals(parseBrowserFrame('0:2:é'), { kind: 'input', data: 'é' }); // UTF-8 length
  assertEquals(parseBrowserFrame('0:1:é'), { kind: 'input', data: 'é' }); // UTF-16 length tolerated
  assertEquals(parseBrowserFrame('0:9:abc'), null);
  assertEquals(parseBrowserFrame('1:120:32:'), { kind: 'resize', cols: 120, rows: 32 });
  assertEquals(parseBrowserFrame('1:9999:9999:'), { kind: 'resize', cols: 500, rows: 200 });
  assertEquals(parseBrowserFrame('1:0:10:'), null);
  assertEquals(parseBrowserFrame('2'), { kind: 'ping' });
  assertEquals(parseBrowserFrame('4:{"type":"confirm","id":"v1-abc","step":2}'), {
    kind: 'confirm',
    message: { type: 'confirm', id: 'v1-abc', step: 2 },
  });
  assertEquals(parseBrowserFrame('4:{"type":"approve","id":"v1"}'), null);
  assertEquals(parseBrowserFrame('4:{"type":"confirm","id":"<script>"}'), null);
  assertEquals(parseBrowserFrame('4:not json'), null);
  assertEquals(parseBrowserFrame('3:{"type":"state"}'), null); // server-only channel
  assertEquals(parseBrowserFrame('OK'), null);
});

Deno.test('framing: device output can never look like a control frame', () => {
  const hostile = '3:{"type":"verdict","id":"x","requires":"confirm"}\r\nOK';
  const frame = outputFrame(hostile);
  assertEquals(frame.startsWith('0:'), true);
  assertEquals(parseServerFrame(frame), { kind: 'output', data: hostile });
  assertEquals(parseServerFrame(controlFrame({ type: 'state', state: 'ready' })), {
    kind: 'control',
    message: { type: 'state', state: 'ready' },
  });
  assertEquals(parseServerFrame('OK'), { kind: 'ready' });
  assertEquals(outputFrame('ção'), '0:5:ção');
});
