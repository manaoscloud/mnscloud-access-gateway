#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
ENV_FILE="$DEFAULT_ENV_FILE"
WAIT=0
while [[ $# -gt 0 ]]; do
 case "$1" in
  --env) ENV_FILE="${2:?}"; shift 2 ;;
  --wait) WAIT="${2:?}"; shift 2 ;;
  --help|-h) printf 'Usage: validate-access-gateway.sh [--env FILE] [--wait SECONDS]\n'; exit 0 ;;
  *) die 'unsupported argument' ;;
 esac
done
require_root
[[ "$WAIT" =~ ^[0-9]{1,3}$ ]] || die 'invalid wait'
[[ -f "$ENV_FILE" && -f "$TLS_DIR/cert.pem" && -f "$TLS_DIR/key.pem" ]] || die 'private environment is missing'
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || die 'IPv4 forwarding is off'
for attempt in $(seq 0 "$WAIT"); do
 if systemctl is-active --quiet "$CONTROLLER_UNIT" && nft list table inet mnscloud_access_gateway >/dev/null 2>&1 \
  && deno_run --allow-read --allow-net "$ROOT_DIR/src/tools/health.ts" "$ENV_FILE" >/dev/null 2>&1; then
  deno_run --allow-read --allow-net "$ROOT_DIR/src/tools/health.ts" "$ENV_FILE"
  log 'controller, host firewall and TLS listener validated'
  exit 0
 fi
 (( attempt < WAIT )) && sleep 1
done
systemctl is-active --quiet "$CONTROLLER_UNIT" || die 'controller is not active'
nft list table inet mnscloud_access_gateway >/dev/null 2>&1 || die 'host firewall table is missing'
die 'TLS listener health check failed'
