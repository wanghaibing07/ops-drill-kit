#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_ROOT"
source "$PROJECT_ROOT/lib/guard.sh"

guard_require_root
guard_require_vm
guard_require_lab

exec "$PROJECT_ROOT/.venv/bin/python" \
  "$PROJECT_ROOT/scripts/bootstrap_m02_writer.py" "$@"
