import {
  configurationNamespace,
  historyNamespace,
  MON,
  monitoringCapability,
} from './namespaces.ts';
export { MON } from './namespaces.ts';
import type { Observation } from './change.ts';
import { NC, Netconf } from './netconf.ts';
import { Element, only, ProtocolError } from './xml.ts';

export type Phase =
  | 'before'
  | 'loaded'
  | 'pending'
  | 'before-confirm'
  | 'after-confirm';
const fail = () => {
  throw new ProtocolError('OBSERVATION_SCHEMA_UNSUPPORTED');
};
function leaf(parent: Element, name: string, ns: string) {
  const e = only(parent, name, ns);
  if (e.children.length) fail();
  return e.text.trim();
}
function childrenKnown(parent: Element, names: readonly string[], ns: string) {
  if (
    parent.text.trim() ||
    parent.children.some((c) => c.ns !== ns || !names.includes(c.name))
  ) fail();
}
function unique(parent: Element) {
  const names = parent.children.map((c) => `{${c.ns}}${c.name}`);
  if (new Set(names).size !== names.length) fail();
}
export function lockOwner(reply: Element): string {
  if (reply.children.length !== 1) fail();
  const data = only(reply, 'data', NC);
  if (data.children.length !== 1) fail();
  const state = only(data, 'netconf-state', MON);
  if (state.children.length !== 1) fail();
  const stores = only(state, 'datastores', MON);
  childrenKnown(stores, ['datastore'], MON);
  const candidates = stores.children.filter((s) => leaf(s, 'name', MON) === 'candidate');
  if (candidates.length !== 1) fail();
  const candidate = candidates[0];
  childrenKnown(candidate, ['name', 'locks'], MON);
  unique(candidate);
  const locks = only(candidate, 'locks', MON);
  // Juniper's 23.4R1-EVO official sample uses direct children, not RFC6022 global-lock wrapper.
  childrenKnown(locks, ['locked-by-session', 'locked-time'], MON);
  unique(locks);
  const owner = leaf(locks, 'locked-by-session', MON);
  if (!/^\d{1,10}$/.test(owner)) fail();
  return owner;
}
export interface History {
  revision: string;
  client: string;
  pending: boolean;
  foreignQueued: boolean;
}
export function history(reply: Element): History {
  if (reply.children.length !== 1) fail();
  const ns = reply.children[0].ns;
  if (!historyNamespace(ns)) fail();
  const info = only(reply, 'commit-information', ns);
  childrenKnown(info, [
    'commit-history',
    'pending-commit',
    'prepared-commit',
    'rescue-configuration',
  ], ns);
  for (
    const singleton of [
      'pending-commit',
      'prepared-commit',
      'rescue-configuration',
    ]
  ) if (info.children.filter((c) => c.name === singleton).length > 1) fail();
  const entries = info.children.filter((c) => c.name === 'commit-history');
  if (!entries.length || entries.length > 50) fail();
  const seqs = new Set<string>();
  let current: Element | undefined;
  for (const e of entries) {
    childrenKnown(e, [
      'sequence-number',
      'date-time',
      'user',
      'client',
      'comment',
      'configuration-revision',
      'log',
      'commit-confirmed',
    ], ns);
    unique(e);
    const seq = leaf(e, 'sequence-number', ns);
    if (!/^(?:0|[1-4]?\d)$/.test(seq) || seqs.has(seq)) fail();
    seqs.add(seq);
    if (seq === '0') current = e;
  }
  if (!current) fail();
  const revision = leaf(current!, 'configuration-revision', ns);
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(revision)) fail();
  return {
    revision,
    client: leaf(current!, 'client', ns),
    pending: current!.children.some((c) => c.name === 'commit-confirmed'),
    foreignQueued: info.children.some((c) =>
      c.name === 'pending-commit' || c.name === 'prepared-commit'
    ),
  };
}
const META =
  /^\{http:\/\/xml\.juniper\.net\/junos\/[A-Za-z0-9._-]+\/junos\}(?:changed-seconds|changed-localtime|commit-seconds|commit-localtime|commit-user)$/;
/** Memory-only canonical digest. Preserves order, namespaces, semantic attrs and exact leaf text. */
export async function configDigest(reply: Element): Promise<string> {
  if (reply.children.length !== 1) fail();
  const ns = reply.children[0].ns;
  if (!configurationNamespace(ns)) fail();
  const cfg = only(reply, 'configuration', ns);
  function value(e: Element, root = false): unknown {
    if (e.ns !== ns) fail(); // Narrow legacy XML profile; YANG configuration namespaces explicitly unsupported.
    if (e.children.length && e.text.trim()) fail();
    const attrs = [...e.attrs].filter(([k]) => !(root && META.test(k))).sort((
      [a],
      [b],
    ) => a.localeCompare(b));
    return [
      e.ns,
      e.name,
      attrs,
      e.children.length ? '' : e.text,
      e.children.map((c) => value(c)),
    ];
  }
  const b = new TextEncoder().encode(JSON.stringify(value(cfg, true)));
  const digest = await crypto.subtle.digest('SHA-256', b);
  return [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, '0'))
    .join('');
}
/** All ownership observations come from actual RPC replies, not caller supplied booleans. */
export class JunosObserver {
  private baseline: string | null = null;
  private expected: string | null = null;
  private baselineRevision: string | null = null;
  private ownRevision: string | null = null;
  async observe(
    nc: Netconf,
    phase: Phase,
    signal: AbortSignal,
  ): Promise<Observation> {
    if (!monitoringCapability(nc.capabilities)) {
      throw new ProtocolError('UNSUPPORTED_LOCK_MONITORING');
    }
    const lock = () =>
      nc.rpc(
        `<get><filter type="subtree"><netconf-state xmlns="${MON}"><datastores/></netconf-state></filter></get>`,
        signal,
      );
    const first = lockOwner(await lock());
    if (first !== nc.sessionId || first === '0') {
      throw new ProtocolError('LOCK_OWNERSHIP_LOST');
    }
    const h = history(
      await nc.rpc(
        '<get-commit-information><include-configuration-revision/></get-commit-information>',
        signal,
      ),
    );
    const candidate = await configDigest(
      await nc.rpc(
        '<get-configuration database="candidate" format="xml"/>',
        signal,
      ),
    );
    const running = await configDigest(
      await nc.rpc(
        '<get-configuration database="committed" format="xml"/>',
        signal,
      ),
    );
    // Bracket the reads: timer expiry or session lock revocation during observation is never accepted.
    if (lockOwner(await lock()) !== nc.sessionId) {
      throw new ProtocolError('LOCK_OWNERSHIP_LOST');
    }
    if (h.foreignQueued) throw new ProtocolError('FOREIGN_PENDING_COMMIT');
    if (phase === 'before') {
      if (h.pending || candidate !== running) {
        throw new ProtocolError('BASELINE_UNSAFE');
      }
      this.baseline = running;
      this.baselineRevision = h.revision;
      return { lockHeld: true, pending: 'none', baselineRestored: true };
    }
    if (!this.baseline || !this.baselineRevision) {
      throw new ProtocolError('BASELINE_MISSING');
    }
    if (phase === 'loaded') {
      if (
        h.pending || h.revision !== this.baselineRevision ||
        running !== this.baseline || candidate === running
      ) throw new ProtocolError('CANDIDATE_UNSAFE');
      this.expected = candidate;
      return { lockHeld: true, pending: 'none', baselineRestored: true };
    }
    if (
      !this.expected || running !== this.expected || candidate !== this.expected
    ) throw new ProtocolError('CONFIGURATION_CHANGED_OR_REVERTED');
    if (phase === 'pending') {
      if (
        !h.pending || h.client !== 'netconf' ||
        h.revision === this.baselineRevision
      ) throw new ProtocolError('COMMIT_NOT_OURS');
      this.ownRevision = h.revision;
    } else if (phase === 'before-confirm') {
      if (
        !h.pending || h.revision !== this.ownRevision || h.client !== 'netconf'
      ) throw new ProtocolError('COMMIT_NOT_OURS');
    } else if (h.pending) throw new ProtocolError('CONFIRMATION_UNKNOWN');
    return {
      lockHeld: true,
      pending: phase === 'after-confirm' ? 'none' : 'ours',
      baselineRestored: false,
    };
  }
}
