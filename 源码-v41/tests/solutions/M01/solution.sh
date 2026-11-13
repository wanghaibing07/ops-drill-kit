#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
exec /usr/bin/python3 "$ROOT/scripts/m01_control.py" solution "$@"
