// Prints the latest approved release tag of a runtime product from the control plane cache.
// Fails closed: never infers a release from git tags.

import { canonicalApi } from '../controller/control_plane.ts';

const PRODUCTS = ['mnscloud-access-gateway', 'mnscloud-agent'];

export async function approvedRelease(base: string, product: string): Promise<string> {
  if (!PRODUCTS.includes(product)) throw new Error('Unsupported runtime');
  const response = await fetch(
    `${canonicalApi(base)}/runtime/releases/latest?product=${product}&channel=stable`,
    {
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
    },
  );
  const text = await response.text();
  if (!response.ok || text.length > 1048576) throw new Error('Invalid release response');
  const ref = JSON.parse(text)?.data?.ref;
  if (typeof ref !== 'string' || !/^v\d+\.\d+\.\d+$/.test(ref)) {
    throw new Error('Invalid approved release');
  }
  return ref;
}

if (import.meta.main) {
  try {
    console.log(await approvedRelease(Deno.args[0], Deno.args[1]));
  } catch {
    console.error('Approved runtime release could not be resolved.');
    Deno.exit(1);
  }
}
