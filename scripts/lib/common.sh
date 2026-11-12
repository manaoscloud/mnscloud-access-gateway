#!/usr/bin/env bash
# shellcheck disable=SC2034
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFAULT_ENV_FILE="/etc/mnscloud/access-gateway.env"
STATE_DIR="/var/lib/mnscloud/access-gateway"
TLS_DIR="/etc/mnscloud/access-gateway/tls"
DENO_CACHE_DIR="/var/cache/mnscloud-access-gateway/deno"
CONTROLLER_UNIT="mnscloud-access-gateway.service"
BRIDGE_DIR="/run/mnscloud-access-gateway-bridge"
SESSION_UNIT_PREFIX="mnscloud-access-gateway-session-"
RUNTIME_KIT_REF="v0.1.76"
RUNTIME_KIT_DIR="/opt/mnscloud/runtime-kit"
DENO_BIN="/usr/local/bin/deno"
log() { printf '[mnscloud-access-gateway] %s\n' "$*"; }
die() { printf '[mnscloud-access-gateway] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ "$EUID" -eq 0 ]] || die 'this command must run as root'; }
parse_common_args() {
 ENV_FILE="$DEFAULT_ENV_FILE"
 while [[ $# -gt 0 ]]; do
  case "$1" in
   --env) [[ $# -ge 2 ]] || die 'missing environment path'; ENV_FILE="$2"; shift 2 ;;
   --help|-h) return 2 ;;
   *) die 'unsupported argument' ;;
  esac
 done
}
# Deno comes only from mnscloud-runtime-kit (pinned ref), like every other runtime.
ensure_runtime_kit() {
 command -v git >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q git </dev/null
 if [[ ! -d "$RUNTIME_KIT_DIR/.git" ]]; then git clone -q https://github.com/manaoscloud/mnscloud-runtime-kit.git "$RUNTIME_KIT_DIR"; fi
 git -C "$RUNTIME_KIT_DIR" fetch -q origin tag "$RUNTIME_KIT_REF"
 git -C "$RUNTIME_KIT_DIR" checkout -q --detach "$RUNTIME_KIT_REF"
}
ensure_deno() {
 if [[ ! -x "$DENO_BIN" ]]; then
  ensure_runtime_kit
  bash "$RUNTIME_KIT_DIR/scripts/install-tool.sh" --tool deno
 fi
 [[ -x "$DENO_BIN" ]] || die 'Deno is not installed'
}
# Sandboxed workers run as dynamic users: the runtime tree must be world-readable (never writable).
fix_runtime_permissions() {
 find "$ROOT_DIR" -path "$ROOT_DIR/.git" -prune -o -exec chmod go+rX,go-w {} +
}
# Listener certificate: self-signed end-entity (CA:FALSE, serverAuth). rustls refuses a CA
# certificate presented by a server (CaUsedAsEndEntity), so the openssl default (CA:TRUE) breaks
# the health probe and every pinned client. Usage: write_listener_certificate <dir> <address>.
write_listener_certificate() {
 local dir="$1" address="$2"
 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
  -subj "/CN=mnscloud-access-gateway" -addext "subjectAltName=IP:$address" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$dir/key.pem.new" -out "$dir/cert.pem.new" >/dev/null 2>&1
 chmod 0600 "$dir/key.pem.new" "$dir/cert.pem.new"
 mv -f "$dir/key.pem.new" "$dir/key.pem"
 mv -f "$dir/cert.pem.new" "$dir/cert.pem"
}
# True when the listener certificate must be (re)written: missing, expiring within 30 days, or a
# CA certificate written by an earlier installer.
listener_certificate_stale() {
 local cert="$1/cert.pem"
 [[ -f "$cert" ]] || return 0
 openssl x509 -checkend 2592000 -noout -in "$cert" >/dev/null 2>&1 || return 0
 openssl x509 -noout -ext basicConstraints -in "$cert" 2>/dev/null | grep -q 'CA:TRUE' && return 0
 return 1
}
deno_run() {
 DENO_DIR="$DENO_CACHE_DIR" DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 "$DENO_BIN" run --cached-only --frozen --no-prompt \
  "--config=$ROOT_DIR/deno.json" "$@"
}
# Type-checks the controller and worker offline: proves the vendored dependencies are complete.
check_runtime() {
 install -d -m 0755 "$(dirname "$DENO_CACHE_DIR")"
 install -d -m 0700 "$DENO_CACHE_DIR"
 DENO_DIR="$DENO_CACHE_DIR" DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 "$DENO_BIN" check --frozen \
  "--config=$ROOT_DIR/deno.json" "$ROOT_DIR/src/controller/main.ts" "$ROOT_DIR/src/worker/main.ts" >/dev/null
}
