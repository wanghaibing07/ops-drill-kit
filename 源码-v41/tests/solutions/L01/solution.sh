#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec /usr/bin/python3 "$HERE/solution.py" "$@"
