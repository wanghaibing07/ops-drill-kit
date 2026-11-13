#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# == 1 && $1 =~ ^[0-9a-f]{24}$ ]] || { echo 'expected run ID' >&2; exit 2; }
exec /usr/bin/python3 -I -B -c "import runpy,sys;sys.path.insert(0,'/usr/local/libexec/opsdrill/m01');runpy.run_path('/usr/local/libexec/opsdrill/m01/m01_owned.py',run_name='__main__')" resolve "$1"
