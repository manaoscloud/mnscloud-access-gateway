#!/usr/bin/env bash
# Applies the release the platform wants this connector to run (root oneshot of the update timer).
# The desired release comes from the signed API configuration; the tag must resolve to the
# announced commit. A release that does not start is rolled back to the previous commit.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/connector.sh
source "$ROOT_DIR/scripts/lib/connector.sh"
connector_require_root
umask 0077
[[ -f "$CONNECTOR_CONFIG" ]] || cdie 'the connector is not installed'
install -d -m 0700 "$CONNECTOR_ROOT_CACHE_DIR"
desired="$(DENO_DIR="$CONNECTOR_ROOT_CACHE_DIR" DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 "$DENO_BIN" run \
 --cached-only --frozen --no-prompt "--config=$CONNECTOR_APP_DIR/deno.json" \
 "--allow-read=$CONNECTOR_APP_DIR,$CONNECTOR_CONF_DIR" --allow-net \
 "$CONNECTOR_APP_DIR/src/connector/main.ts" desired --config "$CONNECTOR_CONFIG" 2>/dev/null || true)"
[[ -n "$desired" ]] || { clog 'no desired release announced'; exit 0; }
tag="$(printf '%s' "$desired" | sed -n 's/.*"tag":"\(v[0-9.]*\)".*/\1/p')"
commit="$(printf '%s' "$desired" | sed -n 's/.*"commit":"\([0-9a-f]\{40\}\)".*/\1/p')"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$commit" =~ ^[0-9a-f]{40}$ ]] || cdie 'the announced release is invalid'
previous="$(git -C "$CONNECTOR_APP_DIR" rev-parse HEAD)"
if [[ "$previous" == "$commit" ]]; then clog "already on $tag"; exit 0; fi
connector_checkout "$tag" "$commit"
apply() {
 connector_ensure_deno
 connector_fix_permissions
 connector_check_runtime
 connector_render_units
 systemctl restart "$CONNECTOR_UNIT"
 sleep 10
 systemctl is-active --quiet "$CONNECTOR_UNIT"
}
if apply; then
 clog "updated to $tag"
 exit 0
fi
clog "release $tag did not start; restoring $previous"
git -C "$CONNECTOR_APP_DIR" checkout -q --detach "$previous"
connector_fix_permissions
systemctl restart "$CONNECTOR_UNIT" || true
cdie 'update failed; the previous release was restored'
