#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CLI="$ROOT/bin/opsdrill"
rid=''
if (( $# != 0 || EUID != 0 )); then printf 'L04 contract requires root and no arguments\n' >&2; exit 2; fi
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n $rid ]]; then
    if ! "$CLI" reset L04 --expect-run-id "$rid"; then
      printf 'L04 owned cleanup failed; retain state and inspect\n' >&2
      (( rc != 0 )) || rc=1
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
receipt="$("$CLI" start L04)"
rid="$(printf '%s' "$receipt" | /usr/bin/python3 -c '
import json,re,sys
o=json.load(sys.stdin); r=o.get("run_id","")
if not re.fullmatch(r"[0-9a-f]{24}",r) or o!={"receipt":"L04_RUN_OWNER_V1","run_id":r,"unit":"opsdrill-l04-"+r+"-fault.service"}: raise SystemExit("invalid receipt")
print(r)
')"
wrong=000000000000000000000000
[[ $rid != "$wrong" ]] || wrong=ffffffffffffffffffffffff
rc=0
"$CLI" reset L04 --expect-run-id "$wrong" || rc=$?
[[ $rc == 2 ]] || { echo 'wrong run did not return refusal 2' >&2; exit 1; }
rc=0
fault="$("$CLI" check L04 --expect-run-id "$rid")" || rc=$?
[[ $rc == 1 ]] || { echo 'fault check did not return 1' >&2; exit 1; }
printf '%s' "$fault" | /usr/bin/python3 -c 'import json,sys; x=json.load(sys.stdin); p=x["probe"]; assert x["status"]=="FAULT" and p["errno"]==24 and p["opened"]<48 and p["health"]=="ok"'
"$CLI" resolve L04 --expect-run-id "$rid"
fixed="$("$CLI" check L04 --expect-run-id "$rid")"
printf '%s' "$fixed" | /usr/bin/python3 -c 'import json,sys; x=json.load(sys.stdin); p=x["probe"]; assert x["status"]=="RECOVERED" and p["errno"] is None and p["opened"]==48 and p["health"]=="ok"'
"$CLI" reset L04 --expect-run-id "$rid"
"$CLI" reset L04 --expect-run-id "$rid"
rid=''
printf 'L04 CLI contract PASS\n'
