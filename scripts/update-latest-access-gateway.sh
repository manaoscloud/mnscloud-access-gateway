#!/usr/bin/env bash
# Manual bootstrap/recovery helper (normal updates use the Agent runtime rollout): checks out the
# latest approved release of the control plane cache and applies it.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
ENV_FILE="$DEFAULT_ENV_FILE"
API_BASE=""
while [[ $# -gt 0 ]]; do
 case "$1" in
  --env) ENV_FILE="${2:?}"; shift 2 ;;
  --api-base) API_BASE="${2:?}"; shift 2 ;;
  --channel) [[ "${2:-}" == stable ]] || die 'only stable is supported'; shift 2 ;;
  --help|-h) printf 'Usage: update-latest-access-gateway.sh [--api-base HTTPS_URL] [--env FILE]\n'; exit 0 ;;
  *) die 'unsupported update argument' ;;
 esac
done
require_root
ensure_deno
if [[ -z "$API_BASE" ]]; then
 API_BASE="$(sed -n 's/^MNSCLOUD_API_BASE_URL=//p' "$ENV_FILE" | head -n 1)"
 [[ -n "$API_BASE" ]] || die 'private environment is invalid'
fi
ref="$(deno_run --allow-net "$ROOT_DIR/src/tools/approved_release.ts" "$API_BASE" mnscloud-access-gateway)" || die 'approved runtime release unavailable'
git -C "$ROOT_DIR" diff --quiet || die 'runtime checkout has local changes'
git -C "$ROOT_DIR" fetch -q origin tag "$ref"
git -C "$ROOT_DIR" cat-file -e "$ref:scripts/update-access-gateway.sh" 2>/dev/null || die 'the requested release is not an access gateway release'
git -C "$ROOT_DIR" checkout -q --detach "$ref"
exec "$ROOT_DIR/scripts/update-access-gateway.sh" --env "$ENV_FILE"
