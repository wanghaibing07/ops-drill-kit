#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
# Match M01 wrappers: controller provides redundant root/VM/marker checks.
# shellcheck source=/dev/null
source "$ROOT/lib/guard.sh"
guard_require_root
guard_require_lab
exec /usr/bin/python3 "$ROOT/drills/linux/L03/l03_control.py" inject "$@"
