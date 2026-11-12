#!/usr/bin/env bash
# Installs the MNSCloud access connector on a Debian/Ubuntu host of the tenant network.
# Run the command shown in the App (Rede > Conectores > Instalar): it downloads this script,
# checks its SHA-256 and runs it as root with the single-use token in the environment
# (never on a command line):
#
#   MNSCLOUD_CONNECTOR_TOKEN   single-use install token (24 h)
#   MNSCLOUD_API_URL           public API base (https://...)
#   MNSCLOUD_CONNECTOR_RELEASE release tag (vX.Y.Z)
#   MNSCLOUD_CONNECTOR_COMMIT  expected 40-hex commit of that tag
#
# The Ed25519 key is generated on this host; only the public key is sent to the platform.
set -Eeuo pipefail
umask 0077
TOKEN="${MNSCLOUD_CONNECTOR_TOKEN:-}"
API_URL="${MNSCLOUD_API_URL:-}"
RELEASE="${MNSCLOUD_CONNECTOR_RELEASE:-}"
COMMIT="${MNSCLOUD_CONNECTOR_COMMIT:-}"
unset MNSCLOUD_CONNECTOR_TOKEN
fail() { printf '[mnscloud-access-connector] ERROR: %s\n' "$*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || fail 'run this command with sudo'
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || fail 'MNSCLOUD_CONNECTOR_TOKEN is missing or invalid; generate a new command in the App'
[[ "$API_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/api(/v1)?)?/?$ ]] || fail 'MNSCLOUD_API_URL must be the https API base'
[[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'MNSCLOUD_CONNECTOR_RELEASE is invalid'
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail 'MNSCLOUD_CONNECTOR_COMMIT is invalid'
API_HOST="${API_URL#https://}"
API_HOST="${API_HOST%%/*}"

# Bootstrap: only what is needed to fetch the pinned release; everything else comes from it.
command -v git >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q git ca-certificates </dev/null
APP_DIR="/opt/mnscloud-access-connector"
REPO="https://github.com/manaoscloud/mnscloud-access-gateway.git"
if [[ ! -d "$APP_DIR/.git" ]]; then
 install -d -m 0755 "$APP_DIR"
 git clone -q "$REPO" "$APP_DIR"
fi
git -C "$APP_DIR" fetch -q --force origin "refs/tags/$RELEASE:refs/tags/$RELEASE"
[[ "$(git -C "$APP_DIR" rev-parse "refs/tags/$RELEASE^{commit}")" == "$COMMIT" ]] || fail "release $RELEASE does not match the expected commit; refusing"
git -C "$APP_DIR" checkout -q --detach "$COMMIT"
# shellcheck source=scripts/lib/connector.sh
source "$APP_DIR/scripts/lib/connector.sh"
connector_check_platform
connector_ensure_deno
connector_fix_permissions
connector_check_runtime

id -u "$CONNECTOR_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$CONNECTOR_USER"
install -d -m 0750 -o root -g "$CONNECTOR_USER" "$CONNECTOR_CONF_DIR"
# Re-installation replaces the key: stop the service and keep the old key until the claim worked.
systemctl stop "$CONNECTOR_UNIT" >/dev/null 2>&1 || true
if [[ -e "$CONNECTOR_KEY" ]]; then mv -f "$CONNECTOR_KEY" "$CONNECTOR_KEY.previous"; fi
install -d -m 0700 "$CONNECTOR_ROOT_CACHE_DIR"
if printf '%s' "$TOKEN" | DENO_DIR="$CONNECTOR_ROOT_CACHE_DIR" DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 "$DENO_BIN" run \
 --cached-only --frozen --no-prompt "--config=$APP_DIR/deno.json" \
 "--allow-read=$APP_DIR,$CONNECTOR_CONF_DIR" "--allow-write=$CONNECTOR_CONF_DIR" "--allow-net=$API_HOST" --allow-sys=hostname \
 "$APP_DIR/src/connector/main.ts" claim --api-url "$API_URL" --config "$CONNECTOR_CONFIG" --key-file "$CONNECTOR_KEY"; then
 rm -f "$CONNECTOR_KEY.previous"
else
 [[ -e "$CONNECTOR_KEY.previous" ]] && mv -f "$CONNECTOR_KEY.previous" "$CONNECTOR_KEY"
 fail 'the platform refused the installation token; generate a new command in the App'
fi
TOKEN=""
chown "$CONNECTOR_USER:$CONNECTOR_USER" "$CONNECTOR_KEY"
chmod 0600 "$CONNECTOR_KEY"
chown "root:$CONNECTOR_USER" "$CONNECTOR_CONFIG"
chmod 0640 "$CONNECTOR_CONFIG"

connector_render_units
systemctl enable --now "$CONNECTOR_UNIT" "$CONNECTOR_UPDATE_TIMER" >/dev/null
for _ in $(seq 1 30); do
 systemctl is-active --quiet "$CONNECTOR_UNIT" && break
 sleep 1
done
systemctl is-active --quiet "$CONNECTOR_UNIT" || fail 'the connector service did not start; see journalctl -u mnscloud-access-connector'
clog "connector installed and running (release $RELEASE); it only opens outbound HTTPS to $API_HOST and the assigned gateway"
