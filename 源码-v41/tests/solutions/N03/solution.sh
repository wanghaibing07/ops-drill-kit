#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
if [[ ${1:-} == --help ]]; then
  printf 'Usage: %s RUN_ID\nResolve the owned N03 run without resetting it.\n' "$0"
  exit 0
fi
if (( $# != 1 )) || [[ ! $1 =~ ^[0-9a-f]{24}$ ]]; then
  printf 'N03 solution: expected one 24-character run ID\n' >&2
  exit 2
fi
exec /usr/bin/python3 "$ROOT/drills/network/N03/n03_502.py" resolve "$1"
