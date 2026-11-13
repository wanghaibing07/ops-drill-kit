#!/usr/bin/env bash
set -Eeuo pipefail
exec /usr/bin/python3 /usr/local/libexec/opsdrill/n01/n01.py inject "$@"
