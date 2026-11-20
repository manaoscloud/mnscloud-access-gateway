import { NC } from './netconf.ts';
export const XNM = 'http://xml.juniper.net/xnm/1.1/xnm'; // NOSONAR namespace identifier, not a URL that is fetched
export const MON = 'urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring';
// Only inherited NETCONF namespace is currently backed by the accepted profile.
// Do not add a versioned junos-system URI without an official wire fixture.
export function historyNamespace(ns: string) {
  return ns === NC;
}
export function configurationNamespace(ns: string) {
  return ns === NC || ns === XNM;
}
export function monitoringCapability(
  capabilities: ReadonlySet<string>,
): boolean {
  for (const cap of capabilities) {
    if (cap === MON) return true;
    if (!cap.startsWith(MON + '?') || cap.length > 1024) continue;
    const query = cap.slice(MON.length + 1);
    if (!/^[A-Za-z0-9_.:,=&%-]+$/.test(query)) continue;
    const params = new URLSearchParams(query);
    let valid = params.get('module') === 'ietf-netconf-monitoring';
    const seen = new Set<string>();
    for (const [k, v] of params) {
      if (
        seen.has(k) ||
        !['module', 'revision', 'features', 'deviations'].includes(k)
      ) valid = false;
      seen.add(k);
      if (k === 'revision' && !/^\d{4}-\d{2}-\d{2}$/.test(v)) valid = false;
      if (
        (k === 'features' || k === 'deviations') &&
        !/^[A-Za-z0-9_.:-]+(?:,[A-Za-z0-9_.:-]+)*$/.test(v)
      ) valid = false;
    }
    if (valid) return true;
  }
  return false;
}
