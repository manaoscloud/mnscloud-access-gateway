#!/usr/bin/env bash
# Applies the checked-out release (the Agent runtime update checks out the approved tag first),
# restarts the controller and validates. A failed validation restores the last good release.
# Active console sessions end on restart (the App reconnects through a new ticket).
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
ENV_FILE="$DEFAULT_ENV_FILE"
ROLLBACK=1
while [[ $# -gt 0 ]]; do
 case "$1" in
  --env) ENV_FILE="${2:?}"; shift 2 ;;
  --no-checkout-rollback) ROLLBACK=0; shift ;;
  --help|-h) printf 'Usage: update-access-gateway.sh [--env FILE]\n'; exit 0 ;;
  *) die 'unsupported update argument' ;;
 esac
done
require_root
umask 0077
[[ -f "$ENV_FILE" ]] || die 'private environment is missing'
install -d -m 0700 "$STATE_DIR"
LAST_GOOD_FILE="$STATE_DIR/last-good-commit"
previous=""
[[ -f "$LAST_GOOD_FILE" ]] && previous="$(tr -cd 'a-f0-9' < "$LAST_GOOD_FILE")"
current="$(git -C "$ROOT_DIR" rev-parse HEAD)"
apply() {
 ensure_deno
 fix_runtime_permissions
 check_runtime
 bash "$ROOT_DIR/scripts/render-units.sh"
 command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables </dev/null >/dev/null
 systemctl restart "$CONTROLLER_UNIT"
 "$ROOT_DIR/scripts/validate-access-gateway.sh" --env "$ENV_FILE" --wait 60
}
if apply; then
 printf '%s\n' "$current" > "$LAST_GOOD_FILE"
 log "access gateway $(tr -d '[:space:]' < "$ROOT_DIR/VERSION") applied and validated"
 exit 0
fi
if (( ROLLBACK == 1 )) && [[ "$previous" =~ ^[a-f0-9]{40}$ && "$previous" != "$current" ]]; then
 log "validation failed; restoring the last good release $previous"
 git -C "$ROOT_DIR" checkout -q --detach "$previous"
 apply || die 'the last good release did not validate either'
 die 'update failed; the last good release was restored'
fi
die 'update failed validation'
