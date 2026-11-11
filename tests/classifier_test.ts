import { Classifier } from '../src/worker/classifier.ts';
import { loadRules } from '../src/worker/rules.ts';
import type { ShellDialect } from '../src/shared/ipc.ts';
import { assertEquals } from './assert.ts';

type Case = [string, string, boolean?];
const fixtures = JSON.parse(
  Deno.readTextFileSync(new URL('./fixtures/classifier.json', import.meta.url)),
) as Record<
  string,
  Case[] | Case[][]
>;

for (const dialect of ['routeros', 'linux', 'proxmox', 'vrp', 'other'] as ShellDialect[]) {
  Deno.test(`classifier fixtures: ${dialect}`, () => {
    const failures: string[] = [];
    for (const [line, expected, unknown] of fixtures[dialect] as Case[]) {
      const result = new Classifier(loadRules(dialect)).classify(line);
      if (result.class !== expected || (unknown !== undefined && result.unknown !== unknown)) {
        failures.push(
          `${JSON.stringify(line)} -> ${result.class}${
            result.unknown ? ' (unknown)' : ''
          } [${result.rule}], expected ${expected}`,
        );
      }
    }
    assertEquals(failures, []);
  });
}

Deno.test('classifier: RouterOS menu context follows navigation that ran', () => {
  for (const sequence of fixtures.routeros_sequences as Case[][]) {
    const classifier = new Classifier(loadRules('routeros'));
    for (const [line, expected] of sequence) {
      const result = classifier.classify(line);
      assertEquals(result.class, expected, `${line} (menu ${classifier.menu || '/'})`);
      if (result.class === 'read') classifier.commit(result);
    }
  }
});

Deno.test('classifier: navigation is not applied before the line runs', () => {
  const classifier = new Classifier(loadRules('routeros'));
  const result = classifier.classify('/ip firewall filter');
  assertEquals(classifier.menu, '');
  classifier.commit(result);
  assertEquals(classifier.menu, '/ip firewall filter');
  assertEquals(classifier.classify('remove 0').class, 'write_risky');
});

Deno.test('classifier: every rule file compiles and every rule is reachable data', () => {
  for (const dialect of ['routeros', 'linux', 'proxmox', 'vrp', 'other'] as ShellDialect[]) {
    const rules = loadRules(dialect);
    assertEquals(rules.rules.length > 0, true, dialect);
    assertEquals(
      new Set(rules.rules.map((r) => r.id)).size,
      rules.rules.length,
      `${dialect} duplicate rule ids`,
    );
  }
});
