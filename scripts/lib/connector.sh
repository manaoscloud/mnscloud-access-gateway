#!/usr/bin/env bash
# Shared by the connector install, update and uninstall scripts (tenant host, not a gateway).
# shellcheck disable=SC2034
set -Eeuo pipefail
CONNECTOR_APP_DIR="/opt/mnscloud-access-connector"
CONNECTOR_CONF_DIR="/etc/mnscloud-access-connector"
CONNECTOR_CONFIG="$CONNECTOR_CONF_DIR/connector.json"
CONNECTOR_KEY="$CONNECTOR_CONF_DIR/key.pkcs8"
CONNECTOR_USER="mns-connector"
CONNECTOR_UNIT="mnscloud-access-connector.service"
CONNECTOR_UPDATE_UNIT="mnscloud-access-connector-update.service"
CONNECTOR_UPDATE_TIMER="mnscloud-access-connector-update.timer"
CONNECTOR_CACHE_DIR="/var/cache/mnscloud-access-connector"
CONNECTOR_ROOT_CACHE_DIR="/var/cache/mnscloud-access-connector-root"
CONNECTOR_REPO="https://github.com/manaoscloud/mnscloud-access-gateway.git"
RUNTIME_KIT_REF="v0.1.76"
RUNTIME_KIT_COMMIT="3ca5ae172bb1e2ec5ebe78e725a25fdd35903540"
RUNTIME_KIT_DIR="/opt/mnscloud-access-connector-runtime-kit"
DENO_BIN="/usr/local/bin/deno"
clog() { printf '[mnscloud-access-connector] %s\n' "$*"; }
cdie() { printf '[mnscloud-access-connector] ERROR: %s\n' "$*" >&2; exit 1; }
connector_require_root() { [[ "$EUID" -eq 0 ]] || cdie 'this command must run as root'; }

# Debian 12/13 and Ubuntu 22.04/24.04 on amd64/arm64.
connector_check_platform() {
 [[ -r /etc/os-release ]] || cdie 'unsupported system'
 local id version
 id="$(. /etc/os-release && printf '%s' "${ID:-}")"
 version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
 case "$id:$version" in
  debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;;
  *) cdie "unsupported system $id $version (Debian 12/13 or Ubuntu 22.04/24.04)" ;;
 esac
 case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) cdie 'unsupported architecture (amd64 or arm64)' ;;
 esac
 command -v systemctl >/dev/null || cdie 'systemd is required'
}

connector_ensure_deno() {
 if [[ ! -x "$DENO_BIN" ]]; then
  if [[ ! -d "$RUNTIME_KIT_DIR/.git" ]]; then git clone -q https://github.com/manaoscloud/mnscloud-runtime-kit.git "$RUNTIME_KIT_DIR"; fi
  git -C "$RUNTIME_KIT_DIR" fetch -q origin tag "$RUNTIME_KIT_REF"
  [[ "$(git -C "$RUNTIME_KIT_DIR" rev-parse "refs/tags/$RUNTIME_KIT_REF^{commit}")" == "$RUNTIME_KIT_COMMIT" ]] || cdie 'runtime-kit release does not match the pinned commit; refusing'
  git -C "$RUNTIME_KIT_DIR" checkout -q --detach "$RUNTIME_KIT_COMMIT"
  bash "$RUNTIME_KIT_DIR/scripts/install-tool.sh" --tool deno
 fi
 [[ -x "$DENO_BIN" ]] || cdie 'Deno is not installed'
}

# The service runs as $CONNECTOR_USER, so Deno and its directories must be executable by that user.
# The deno.land installer can leave its bin directory 0700 (root-only runtimes never notice).
connector_check_service_exec() {
 local real
 real="$(readlink -f "$DENO_BIN")"
 if [[ "$real" == /usr/local/deno/* ]]; then chmod go+rx /usr/local/deno "$(dirname "$real")" "$real"; fi
 runuser -u "$CONNECTOR_USER" -- "$DENO_BIN" --version >/dev/null 2>&1 ||
  cdie "Deno ($real) is not executable by $CONNECTOR_USER; make it and its directories world-executable"
}

# Runtime tree: world-readable, never writable by the service user.
connector_fix_permissions() {
 find "$CONNECTOR_APP_DIR" -path "$CONNECTOR_APP_DIR/.git" -prune -o -exec chmod go+rX,go-w {} +
}

# Offline type check: proves the vendored dependencies are complete.
connector_check_runtime() {
 install -d -m 0700 "$CONNECTOR_ROOT_CACHE_DIR"
 DENO_DIR="$CONNECTOR_ROOT_CACHE_DIR" DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 "$DENO_BIN" check --frozen \
  "--config=$CONNECTOR_APP_DIR/deno.json" "$CONNECTOR_APP_DIR/src/connector/main.ts" >/dev/null
}

# Fetches an exact release and verifies it without touching the working tree: the tag must exist,
# resolve to the expected commit and not be older than the running VERSION (no downgrade).
connector_verify_release() {
 local tag="$1" commit="$2" actual current target
 [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || cdie 'invalid release tag'
 [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || cdie 'invalid release commit'
 git -C "$CONNECTOR_APP_DIR" fetch -q --force origin "refs/tags/$tag:refs/tags/$tag"
 actual="$(git -C "$CONNECTOR_APP_DIR" rev-parse "refs/tags/$tag^{commit}")"
 [[ "$actual" == "$commit" ]] || cdie "release $tag does not match the expected commit; refusing"
 current="$(tr -d '[:space:]' < "$CONNECTOR_APP_DIR/VERSION")"
 target="$(git -C "$CONNECTOR_APP_DIR" show "$commit:VERSION" | tr -d '[:space:]')"
 [[ "$current" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || cdie 'invalid VERSION'
 [[ "$(printf '%s\n%s\n' "$current" "$target" | sort -V | head -n 1)" == "$current" ]] || cdie "release $tag is older than the running $current; refusing a downgrade"
}

# Checks out an exact release (verify first: connector_verify_release).
connector_checkout() {
 local tag="$1" commit="$2"
 connector_verify_release "$tag" "$commit"
 git -C "$CONNECTOR_APP_DIR" checkout -q --detach "$commit"
}

# Unprivileged service plus the root update oneshot and its timer.
connector_render_units() {
 cat > "/etc/systemd/system/$CONNECTOR_UNIT" <<EOF_UNIT
[Unit]
Description=MNSCloud access connector (outbound tunnel to an access gateway)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$CONNECTOR_USER
Group=$CONNECTOR_USER
CacheDirectory=mnscloud-access-connector
Environment=DENO_DIR=$CONNECTOR_CACHE_DIR/deno
Environment=DENO_NO_UPDATE_CHECK=1
Environment=NO_COLOR=1
ExecStart=$DENO_BIN run --cached-only --frozen --no-prompt --config=$CONNECTOR_APP_DIR/deno.json --allow-net --allow-read=$CONNECTOR_APP_DIR,$CONNECTOR_CONF_DIR --allow-sys=hostname,networkInterfaces $CONNECTOR_APP_DIR/src/connector/main.ts run --config $CONNECTOR_CONFIG
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
# OS-level second layer behind the destination checks: never loopback, link-local or multicast
# (the local resolver stub stays reachable for DNS).
IPAddressDeny=localhost link-local multicast
IPAddressAllow=127.0.0.53 127.0.0.54
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=pkey_alloc pkey_free pkey_mprotect
SystemCallFilter=~@privileged @mount @swap @reboot @module @raw-io @debug @cpu-emulation @obsolete
MemoryMax=256M
TasksMax=64
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF_UNIT
 cat > "/etc/systemd/system/$CONNECTOR_UPDATE_UNIT" <<EOF_UPDATE
[Unit]
Description=MNSCloud access connector release update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$CONNECTOR_APP_DIR/scripts/update-connector.sh
TimeoutStartSec=600
NoNewPrivileges=yes
EOF_UPDATE
 cat > "/etc/systemd/system/$CONNECTOR_UPDATE_TIMER" <<EOF_TIMER
[Unit]
Description=MNSCloud access connector release update check

[Timer]
OnBootSec=10min
OnUnitActiveSec=30min
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF_TIMER
 chmod 0644 "/etc/systemd/system/$CONNECTOR_UNIT" "/etc/systemd/system/$CONNECTOR_UPDATE_UNIT" "/etc/systemd/system/$CONNECTOR_UPDATE_TIMER"
 systemctl daemon-reload
}
