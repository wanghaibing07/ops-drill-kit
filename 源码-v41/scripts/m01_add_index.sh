#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo "Run through sudo" >&2; exit 1; }
# shellcheck source=/dev/null
source /opt/ops-drill-kit/lib/guard.sh
guard_require_lab
exec 9>/run/lock/opsdrill-m01-index.lock
flock -n 9 || { echo "Index change already running" >&2; exit 1; }
mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf < /opt/ops-drill-kit/sql/007_m01_add_index.sql
