#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 1 && $1 =~ ^[0-9a-f]{24}$ ]] || { echo 'expected run ID' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
exec "$root/bin/opsdrill" resolve L02 --expect-run-id "$1"
