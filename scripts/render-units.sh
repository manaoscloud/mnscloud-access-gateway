#!/usr/bin/env bash
# Writes the controller unit and the kernel prerequisites (forwarding for the session namespaces).
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
require_root
cat > /etc/sysctl.d/90-mnscloud-access-gateway.conf <<'EOF_SYSCTL'
# MNSCloud access gateway: session namespaces are routed (and masqueraded) by this host.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Keep router advertisements on new interfaces while forwarding is on.
net.ipv6.conf.default.accept_ra = 2
EOF_SYSCTL
chmod 0644 /etc/sysctl.d/90-mnscloud-access-gateway.conf
sysctl -q -p /etc/sysctl.d/90-mnscloud-access-gateway.conf
cat > "/etc/systemd/system/$CONTROLLER_UNIT" <<EOF_UNIT
[Unit]
Description=MNSCloud access gateway controller
Wants=network-online.target
After=network-online.target nftables.service

[Service]
Type=simple
Environment=DENO_DIR=$DENO_CACHE_DIR
Environment=DENO_NO_UPDATE_CHECK=1
Environment=NO_COLOR=1
ExecStart=$DENO_BIN run --cached-only --frozen --no-prompt --config=$ROOT_DIR/deno.json --allow-net --allow-read --allow-write=$STATE_DIR --allow-run=systemd-run,systemctl,ip,nft $ROOT_DIR/src/controller/main.ts --env $DEFAULT_ENV_FILE
ExecStopPost=$ROOT_DIR/scripts/cleanup-sessions.sh
Restart=always
RestartSec=5
TimeoutStopSec=30
UMask=0077
# No mount namespace (PrivateTmp/ProtectSystem/ProtectHome): the session namespaces the
# controller creates under /run/netns must be visible to systemd, which starts each worker in one.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_UNIT
chmod 0644 "/etc/systemd/system/$CONTROLLER_UNIT"
systemctl daemon-reload
