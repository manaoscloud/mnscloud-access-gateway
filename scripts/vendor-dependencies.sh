#!/usr/bin/env bash
# Development helper: refreshes the vendored npm dependencies (node_modules/ + deno.lock) and prunes
# what the runtime never loads (tests with sample keys, examples, native addon sources, optional
# native packages). Commit the result; hosts never download dependencies.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
sed -i 's/"frozen": true/"frozen": false/' deno.json
trap 'sed -i "s/\"frozen\": false/\"frozen\": true/" deno.json' EXIT
deno install
store=node_modules/.deno
rm -rf "$store"/cpu-features@* "$store"/nan@* "$store"/buildcheck@* \
 "$store"/node_modules/cpu-features "$store"/node_modules/nan "$store"/node_modules/buildcheck
for pkg in "$store"/ssh2@*/node_modules/ssh2; do
 rm -rf "$pkg/test" "$pkg/examples" "$pkg/install.js" "$pkg/lib/protocol/crypto/src" "$pkg/lib/protocol/crypto/binding.gyp"
done
find "$store" -xtype l -delete
if grep -rlE '^-----BEGIN [A-Z ]*PRIVATE KEY-----\s*$' node_modules >/dev/null; then
 printf 'vendored dependencies still contain key material\n' >&2
 exit 1
fi
printf 'vendored dependencies refreshed\n'
