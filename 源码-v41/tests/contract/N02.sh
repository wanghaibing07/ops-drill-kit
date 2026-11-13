#!/usr/bin/env bash
# This is a real mutating integration contract: run only in the authorized VM.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
controller=/usr/local/libexec/opsdrill/n02/n02.py
/usr/bin/python3 "$controller" inspect-clean
receipt=$(/usr/bin/python3 "$controller" start)
run_id=$(printf '%s' "$receipt" | /usr/bin/python3 -c 'import json,re,sys; x=json.load(sys.stdin); assert set(x)=={"receipt","run_id"} and x["receipt"]=="N02_OWNER_V1" and re.fullmatch("[0-9a-f]{24}",x["run_id"]); print(x["run_id"])')
trap 'echo "N02 contract interrupted; inspect run $run_id before reset" >&2' ERR
/usr/bin/python3 "$controller" verify-owner "$run_id"
if /usr/bin/python3 "$controller" check "$run_id"; then
  rc=0
else
  rc=$?
fi
[[ $rc == 1 ]] || { echo "expected fault status 1; got $rc" >&2; exit 1; }
"$root/tests/solutions/N02.sh" "$run_id"
/usr/bin/python3 "$controller" check "$run_id"
/usr/bin/python3 "$controller" reset "$run_id"
/usr/bin/python3 "$controller" reset "$run_id"
/usr/bin/python3 "$controller" inspect-clean
