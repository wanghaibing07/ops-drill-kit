#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run through sudo' >&2; exit 1; }
# shellcheck source=/dev/null
source /opt/ops-drill-kit/lib/guard.sh
guard_require_lab
exec 9>/run/lock/opsdrill-legacy-archive.lock
flock -n 9 || { echo 'Archive already running' >&2; exit 1; }
exec /opt/ops-drill-kit/.venv/bin/python /opt/ops-drill-kit/scripts/archive_legacy.py
