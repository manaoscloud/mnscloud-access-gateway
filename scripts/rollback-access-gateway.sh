#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
require_root
[[ "${1:-}" == --ref && "${2:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Usage: rollback-access-gateway.sh --ref <previous-approved-tag> [--env FILE]'
ref="$2"
shift 2
ENV_FILE="$DEFAULT_ENV_FILE"
if [[ "${1:-}" == --env ]]; then ENV_FILE="${2:?}"; fi
git -C "$ROOT_DIR" diff --quiet || die 'runtime checkout has local changes'
git -C "$ROOT_DIR" fetch -q origin tag "$ref"
git -C "$ROOT_DIR" cat-file -e "$ref:scripts/update-access-gateway.sh" 2>/dev/null || die 'the requested release is not an access gateway release'
git -C "$ROOT_DIR" checkout -q --detach "$ref"
exec "$ROOT_DIR/scripts/update-access-gateway.sh" --env "$ENV_FILE" --no-checkout-rollback
