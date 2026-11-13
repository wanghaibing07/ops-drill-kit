#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then
    echo 'Run through sudo; default mode is read-only.' >&2
    exit 1
fi
# shellcheck source=/dev/null
source /opt/ops-drill-kit/lib/guard.sh
guard_require_lab
exec 9>/run/lock/opsdrill-stage3-import.lock
flock -n 9 || { echo 'Another import is running' >&2; exit 1; }
exec /opt/ops-drill-kit/.venv/bin/python /opt/ops-drill-kit/scripts/promote_orders_segment.py "$@"
