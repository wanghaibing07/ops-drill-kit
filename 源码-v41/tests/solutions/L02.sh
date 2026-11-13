#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -ge 1 && $# -le 2 && $1 =~ ^[0-9a-f]{24}$ ]] || { echo 'expected run ID and optional actor' >&2; exit 2; }
actor=${2:-unknown}
[[ $actor == user || $actor == agent || $actor == unknown ]] || { echo 'invalid actor' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
exec "$root/bin/opsdrill" resolve L02 --expect-run-id "$1" --actor "$actor"
