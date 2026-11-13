#!/usr/bin/env bash
# Mutating integration contract: only in the authorized isolated lab.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
receipt=$("$root/bin/opsdrill" start M01 --actor agent)
run_id=$(printf '%s' "$receipt" | /usr/bin/python3 -c 'import json,re,sys; x=json.load(sys.stdin); assert x["receipt"]=="M01_INDEX_OWNER_V1" and re.fullmatch("[0-9a-f]{24}",x["run_id"]); print(x["run_id"])')
trap 'echo "M01 contract interrupted; inspect run $run_id before reset" >&2' ERR
if "$root/bin/opsdrill" check M01 --actor agent --expect-run-id "$run_id"; then rc=0; else rc=$?; fi
[[ $rc == 1 ]] || { echo "expected fault status 1; got $rc" >&2; exit 1; }
"$root/tests/solutions/M01/owned_solution.sh" "$run_id"
"$root/bin/opsdrill" check M01 --actor agent --expect-run-id "$run_id"
"$root/bin/opsdrill" reset M01 --actor agent --expect-run-id "$run_id"
"$root/bin/opsdrill" reset M01 --actor agent
