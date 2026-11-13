#!/usr/bin/env bash
set -Eeuo pipefail
exec /usr/bin/python3 -I -B -c "import runpy,sys;sys.path.insert(0,'/usr/local/libexec/opsdrill/l02');runpy.run_path('/usr/local/libexec/opsdrill/l02/l02_cli.py',run_name='__main__')" "$@"
