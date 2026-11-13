#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CLI="$ROOT/bin/opsdrill"
CONTROLLER="$ROOT/drills/network/N03/n03_502.py"
SOLUTION="$ROOT/tests/solutions/N03/solution.sh"
run_id=''
if [[ ${1:-} == --help ]]; then
  printf 'Usage: sudo %s\nRun the guarded N03 502 and 504 CLI contracts as actor=agent.\n' "$0"
  exit 0
fi
if (( $# != 0 || EUID != 0 )); then
  printf 'N03 contract: no arguments and root are required\n' >&2
  exit 2
fi
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n $run_id ]]; then
    if ! "$CLI" reset N03 --actor agent --expect-run-id "$run_id"; then
      printf 'N03 contract: owned cleanup failed; preserve and inspect the run\n' >&2
      (( rc != 0 )) || rc=1
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
expect_rc() {
  local expected=$1 actual
  shift
  if "$@"; then actual=0; else actual=$?; fi
  if (( actual != expected )); then
    printf 'N03 contract: expected exit %s, got %s\n' "$expected" "$actual" >&2
    return 1
  fi
}
/usr/bin/python3 "$CONTROLLER" inspect-clean
"$CLI" status | /usr/bin/grep -qx 'N03 NO_CLI_STATE'
expect_rc 2 "$CLI" check N03 --actor agent
for variant in 502 504; do
  printf 'N03 contract: %s\n' "$variant"
  receipt="$("$CLI" start N03 --variant "$variant" --actor agent)"
  run_id="$(printf '%s' "$receipt" | /usr/bin/python3 -c '
import json, re, sys
v = sys.argv[1]
obj = json.load(sys.stdin)
rid = obj.get("run_id", "")
if (not re.fullmatch(r"[0-9a-f]{24}", rid) or
    obj.get("receipt") != "N03_" + v + "_OWNER_V1" or
    obj.get("timer") != "opsdrill-n03-recover-" + rid + ".timer"):
    raise SystemExit("invalid ownership receipt; inspect the controller")
print(rid)
' "$variant")"
  wrong_id=000000000000000000000000
  [[ $run_id != "$wrong_id" ]] || wrong_id=ffffffffffffffffffffffff
  expect_rc 2 "$CLI" reset N03 --actor agent --expect-run-id "$wrong_id"
  expect_rc 1 "$CLI" check N03 --actor agent --expect-run-id "$run_id"
  bash "$SOLUTION" "$run_id"
  expect_rc 0 "$CLI" check N03 --actor agent --expect-run-id "$run_id"
  expect_rc 0 "$CLI" reset N03 --actor agent --expect-run-id "$run_id"
  expect_rc 0 "$CLI" reset N03 --actor agent --expect-run-id "$run_id"
  run_id=''
  expect_rc 2 "$CLI" check N03 --actor agent
  /usr/bin/python3 "$CONTROLLER" inspect-clean
done
printf 'N03 contract: PASS (actor=agent)\n'
