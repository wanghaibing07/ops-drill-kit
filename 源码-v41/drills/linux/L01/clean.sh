#!/usr/bin/env bash
set -Eeuo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
/usr/bin/python3 "$HERE/l01_control.py" inspect-clean
exec /usr/bin/python3 "$HERE/l01_deleted.py" inspect-clean
