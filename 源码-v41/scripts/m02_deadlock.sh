#!/usr/bin/env bash
# Project-owned convenience wrapper: do not run this file through sudo.
set -Eeuo pipefail
if (( EUID == 0 )); then
    echo 'Use the root-controlled M02 launcher directly; do not sudo a project-owned wrapper.' >&2
    exit 2
fi
exec /usr/bin/sudo -- /usr/bin/python3.11 -I -S -B /usr/local/libexec/opsdrill/m02/m02_launcher.py "$@"
