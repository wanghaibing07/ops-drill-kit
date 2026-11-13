#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# == 1 && $1 =~ ^[0-9a-f]{24}$ ]] || { echo 'expected run ID' >&2; exit 2; }
exec /usr/bin/python3 /usr/local/libexec/opsdrill/n02/n02.py repair "$1"
