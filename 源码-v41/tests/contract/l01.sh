#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CLI="$ROOT/bin/opsdrill"
OBSERVER="$ROOT/tests/contract/l01_observe.py"
SOLUTION="$ROOT/tests/solutions/L01/solution.sh"
run_id=''
if [[ ${1:-} == --help ]]; then
  printf 'Usage: sudo %s\nRun guarded L01 inode and deleted-open contracts as actor=agent.\n' "$0"
  exit 0
fi
if (( $# != 0 || EUID != 0 )); then
  printf 'L01 contract: no arguments and root are required\n' >&2
  exit 2
fi
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n $run_id ]]; then
    if ! "$CLI" reset L01 --actor agent --expect-run-id "$run_id"; then
      printf 'L01 contract: owned cleanup failed; preserve and inspect the run\n' >&2
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
    printf 'L01 contract: expected exit %s, got %s\n' "$expected" "$actual" >&2
    return 1
  fi
}
bash "$ROOT/drills/linux/L01/clean.sh"
"$CLI" status | /usr/bin/grep -qx 'L01 NO_CLI_STATE'
expect_rc 2 "$CLI" check L01 --actor agent
for variant in inode deleted-open; do
  printf 'L01 contract: %s\n' "$variant"
  receipt="$("$CLI" start L01 --variant "$variant" --actor agent)"
  parsed="$(printf '%s' "$receipt" | /usr/bin/python3 -c '
import json, re, sys
v = sys.argv[1]
obj = json.load(sys.stdin)
rid = obj.get("run_id", "")
expected = "L01_INODE_OWNER_V1" if v == "inode" else "L01_DELETED_OWNER_V1"
if not re.fullmatch(r"[0-9a-f]{24}", rid) or obj.get("receipt") != expected:
    raise SystemExit("invalid ownership receipt; inspect the controller")
if v == "deleted-open" and obj.get("unit") != "opsdrill-l01-deleted-" + rid + ".service":
    raise SystemExit("invalid unit identity; inspect the controller")
print(rid)
if v == "deleted-open": print(obj["unit"])
' "$variant")"
  run_id="${parsed%%$'\n'*}"
  unit=''
  if [[ $variant == deleted-open ]]; then unit="${parsed#*$'\n'}"; fi
  wrong_id=000000000000000000000000
  [[ $run_id != "$wrong_id" ]] || wrong_id=ffffffffffffffffffffffff
  expect_rc 2 "$CLI" reset L01 --actor agent --expect-run-id "$wrong_id"
  expect_rc 1 "$CLI" check L01 --actor agent --expect-run-id "$run_id"
  before="$(/usr/bin/python3 "$OBSERVER" "$variant" fault "$run_id")"
  printf '%s\n' "$before"
  if [[ $variant == inode ]]; then
    bash "$SOLUTION" "$variant" "$run_id"
  else
    bash "$SOLUTION" "$variant" "$run_id" "$unit"
  fi
  after="$(/usr/bin/python3 "$OBSERVER" "$variant" recovered "$run_id")"
  printf '%s\n' "$after"
  if [[ $variant == deleted-open ]]; then
    /usr/bin/python3 -c '
import json, sys
before, after = (json.loads(x) for x in sys.argv[1:])
if after["available_bytes"] - before["available_bytes"] < 28 * 1024 * 1024:
    raise SystemExit("deleted-open space was not released")
' "$before" "$after"
  fi
  expect_rc 0 "$CLI" check L01 --actor agent --expect-run-id "$run_id"
  expect_rc 0 "$CLI" reset L01 --actor agent --expect-run-id "$run_id"
  expect_rc 0 "$CLI" reset L01 --actor agent --expect-run-id "$run_id"
  run_id=''
  expect_rc 2 "$CLI" check L01 --actor agent
  bash "$ROOT/drills/linux/L01/clean.sh"
done
printf 'L01 contract: PASS (actor=agent)\n'
