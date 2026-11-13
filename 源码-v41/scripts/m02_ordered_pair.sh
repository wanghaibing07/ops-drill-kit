#!/usr/bin/env bash
set -Eeuo pipefail
PROJECT_ROOT="/opt/ops-drill-kit"
cd "$PROJECT_ROOT"
exec "$PROJECT_ROOT/.venv/bin/python" "$PROJECT_ROOT/scripts/m02_ordered_pair.py" "$@"
