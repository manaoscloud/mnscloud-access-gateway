#!/usr/bin/env bash
# Removes every session worker and namespace (controller stop/crash): no session survives the
# controller, and a killed worker leaves nothing behind.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
require_root
systemctl kill --signal=KILL "${SESSION_UNIT_PREFIX}*" >/dev/null 2>&1 || true
systemctl reset-failed "${SESSION_UNIT_PREFIX}*" >/dev/null 2>&1 || true
while read -r name _; do
 if [[ "$name" =~ ^mnsagw-[0-9a-f]{8}$ ]]; then ip netns delete "$name" >/dev/null 2>&1 || true; fi
done < <(ip netns list 2>/dev/null || true)
while read -r link; do
 if [[ "$link" =~ ^agwh[0-9a-f]{8}$ ]]; then ip link delete "$link" >/dev/null 2>&1 || true; fi
done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
exit 0
