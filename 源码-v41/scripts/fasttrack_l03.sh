#!/usr/bin/env bash
# Batch offline checks + optionally one bounded L03 VM run.
# Automatic cleanup is authorized only by a verified receipt for this invocation.
set -Eeuo pipefail
umask 077

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$SELF_DIR/.." && pwd -P)"
MODE="${1:---offline}"
case "$MODE" in --offline|--execute) ;; *) echo 'USAGE: fasttrack_l03.sh --offline|--execute' >&2; exit 64;; esac

EVID="$(mktemp -d /var/tmp/opsdrill-l03-fasttrack.XXXXXXXX)"
chmod 0700 "$EVID"
CHECK_OK=0
CLEAN_OK=0
OWNED_RUN_ID=''
OWNED_UNIT=''
UNIT=''
MONITORS=()

note() { printf '%s\n' "$*"; }
failure() { note "FAIL: $* (evidence: $EVID)" >&2; exit 2; }

stop_monitors() {
  local pid
  for pid in "${MONITORS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; fi
  done
  for pid in "${MONITORS[@]}"; do wait "$pid" 2>/dev/null || true; done
  MONITORS=()
}

capture_owner_receipt() {
  local parsed rid unit
  if ! parsed="$(/usr/bin/python3 "$ROOT/scripts/l03_fasttrack_guard.py" receipt "$EVID/inject.json" 2>"$EVID/receipt-parse.stderr")"; then
    return 1
  fi
  IFS=$'\t' read -r rid unit <<< "$parsed"
  [[ "$rid" =~ ^[0-9a-f]{24}$ ]] || return 1
  [[ "$unit" == "opsdrill-l03-${rid}.service" ]] || return 1
  # Re-open current.json through the controller's dirfd/O_NOFOLLOW path and
  # verify that this exact run_id/unit is still the current owned run.
  if ! /usr/bin/python3 "$ROOT/drills/linux/L03/l03_control.py" verify-owner "$rid" "$unit" \
      >"$EVID/owner-verify.json" 2>"$EVID/owner-verify.stderr"; then
    return 1
  fi
  OWNED_RUN_ID="$rid"
  OWNED_UNIT="$unit"
  UNIT="$unit"
  return 0
}

attempt_reset() {
  # No receipt or failed owner verification means absolutely no reset attempt.
  if [[ -n "$OWNED_RUN_ID" && -n "$OWNED_UNIT" && "$CLEAN_OK" -ne 1 ]]; then
    if timeout --signal=TERM --kill-after=5s 20s bash "$ROOT/drills/linux/L03/reset.sh" \
        "$OWNED_RUN_ID" "$OWNED_UNIT" >"$EVID/reset.log" 2>&1; then
      if [[ ! -e /mnt/opsdrill/L03/current.json ]]; then CLEAN_OK=1; fi
    fi
  fi
}

# Called by the EXIT trap; ShellCheck cannot see this indirect invocation.
# shellcheck disable=SC2317
finalize() {
  local rc=$?
  trap - EXIT INT TERM
  stop_monitors
  attempt_reset
  # System and run evidence must survive reset for later auditing.
  if [[ -n "$UNIT" ]] && command -v journalctl >/dev/null; then
    journalctl --no-pager -u "$UNIT" -n 120 >"$EVID/unit-journal.log" 2>&1 || true
  fi
  printf 'mode=%s\ncheck_pass=%s\ncleanup_pass=%s\nowned_run_id=%s\nowned_unit=%s\nexit_code=%s\n' \
     "$MODE" "$CHECK_OK" "$CLEAN_OK" "${OWNED_RUN_ID:-none}" "${OWNED_UNIT:-none}" "$rc" > "$EVID/summary.txt"
  (cd "$EVID"; find . -maxdepth 1 -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 -r sha256sum > SHA256SUMS) || true
  note "L03 evidence: $EVID"
  exit "$rc"
}
trap finalize EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_gate() {
  local label="$1"; shift
  if "$@" >"$EVID/$label.log" 2>&1; then note "PASS $label"; else failure "$label (see $label.log)"; fi
}

[[ -f "$ROOT/drills/linux/L03/l03_control.py" ]] || failure 'L03 controller missing'
[[ -f "$ROOT/scripts/l03_fasttrack_guard.py" ]] || failure 'L03 receipt validator missing'
[[ -f "$ROOT/lib/guard.sh" ]] || failure 'guard.sh missing'

# Offline gates: no VM dependency, no writes to /mnt/opsdrill.
for name in inject check reset; do
  run_gate "bash_syntax_${name}" bash -n "$ROOT/drills/linux/L03/$name.sh"
done
run_gate bash_syntax_fasttrack bash -n "$ROOT/scripts/fasttrack_l03.sh"
run_gate python_syntax /usr/bin/python3 -c 'import ast,sys; [ast.parse(open(p,encoding="utf-8").read()) for p in sys.argv[1:]]' \
  "$ROOT/drills/linux/L03/l03_control.py" "$ROOT/scripts/l03_fasttrack_guard.py"
run_gate python_unittest /usr/bin/python3 -m unittest discover -s "$ROOT/tests/python" -p 'test_*.py' -v
command -v bats >/dev/null || failure 'bats not found'
run_gate bats bats "$ROOT/tests/bats/l03.bats"
command -v shellcheck >/dev/null || failure 'shellcheck not found'
run_gate shellcheck shellcheck "$ROOT/drills/linux/L03/inject.sh" "$ROOT/drills/linux/L03/check.sh" \
  "$ROOT/drills/linux/L03/reset.sh" "$ROOT/scripts/fasttrack_l03.sh"
run_gate project_inventory /usr/bin/python3 "$ROOT/scripts/opsdrill_inventory.py"
GIT_OPTIONAL_LOCKS=0 git -C "$ROOT" status --short > "$EVID/git-status.txt" 2>&1 || true
GIT_OPTIONAL_LOCKS=0 git -C "$ROOT" rev-parse HEAD > "$EVID/git-commit.txt" 2>&1 || true

if [[ "$MODE" == '--offline' ]]; then
  CHECK_OK=1; CLEAN_OK=1
  note 'OFFLINE_PASS: only static/unit/Bats gates were checked; no VM experiment ran.'
  exit 0
fi

# Real VM gates. Controller repeats these checks before touching experiment files.
[[ "$EUID" -eq 0 ]] || failure 'execute mode requires root'
# shellcheck source=/dev/null
source "$ROOT/lib/guard.sh"
guard_require_root || failure 'guard root gate'
guard_require_lab || failure 'guard lab gate'
[[ "$(systemctl --version | head -n 1 | awk '{print $2}')" =~ ^[0-9]+$ ]] || failure 'systemd unavailable'
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || failure 'cgroup v2 required'
for bin in systemd-run systemctl journalctl timeout iostat pidstat vmstat findmnt curl; do command -v "$bin" >/dev/null || failure "missing $bin"; done
[[ ! -e /mnt/opsdrill/L03/current.json ]] || failure 'existing L03 run; inspect/reset separately'

# Read-only preflight, including unsynchronized clock evidence (no clock changes).
{
  date -Ins
  timedatectl
  chronyc tracking
  chronyc sources -v
} >"$EVID/time-preflight.txt" 2>&1 || true
{
  findmnt -T /mnt/opsdrill -o TARGET,SOURCE,FSTYPE,OPTIONS
  findmnt -T /var/lib/mysql -o TARGET,SOURCE,FSTYPE,OPTIONS
  df -hT /mnt/opsdrill /var/lib/mysql
  for service in mysqld nginx orderguard-api; do systemctl is-active "$service" || exit 2; done
} >"$EVID/host-preflight.txt" 2>&1 || failure 'host preflight'
for endpoint in health ready; do
  curl --noproxy '*' --max-time 3 -fsS -o /dev/null \
    -w "${endpoint}: http=%{http_code} duration=%{time_total}\n" \
    "http://127.0.0.1:8080/$endpoint" >>"$EVID/http-preflight.txt" 2>&1 || failure "HTTP $endpoint preflight"
done

# Baseline metrics before starting the Worker.
vmstat 1 3 >"$EVID/vmstat-before.txt" 2>&1 || true
iostat -xz 1 3 >"$EVID/iostat-before.txt" 2>&1 || true
pidstat -d 1 3 >"$EVID/pidstat-before.txt" 2>&1 || true

vmstat 1 35 >"$EVID/vmstat-during.txt" 2>&1 & MONITORS+=("$!")
iostat -xz 1 35 >"$EVID/iostat-during.txt" 2>&1 & MONITORS+=("$!")
pidstat -d 1 35 >"$EVID/pidstat-during.txt" 2>&1 & MONITORS+=("$!")

# Capture inject's output even on failure: the controller emits a durable owner
# receipt before systemd-run. A failed preflight emits no receipt and cannot reset.
inject_rc=0
bash "$ROOT/drills/linux/L03/inject.sh" >"$EVID/inject.json" 2>"$EVID/inject.stderr" || inject_rc=$?
if ! capture_owner_receipt; then
  failure 'no verified ownership receipt; refusing automatic reset and preserving all state'
fi
if (( inject_rc != 0 )); then
  failure 'inject failed after a verified owned run was created; only that run may be reset'
fi

# Poll until completed/failure/deadline. check exit 2 while RUNNING is expected.
deadline=$((SECONDS + 43))
while (( SECONDS < deadline )); do
  if bash "$ROOT/drills/linux/L03/check.sh" >"$EVID/check-last.json" 2>"$EVID/check-last.stderr"; then
    CHECK_OK=1; break
  fi
  status="$(/usr/bin/python3 - "$EVID/check-last.json" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1],encoding='utf-8')).get('status','UNKNOWN'))
except (ValueError,OSError,TypeError): print('INVALID')
PY
)"
  case "$status" in
    FAILED|INTERRUPTED|INTERRUPTED_OR_START_FAILED|UNKNOWN|INVALID) break;;
  esac
  sleep 1
done

stop_monitors
vmstat 1 3 >"$EVID/vmstat-after.txt" 2>&1 || true
iostat -xz 1 3 >"$EVID/iostat-after.txt" 2>&1 || true
for endpoint in health ready; do
  curl --noproxy '*' --max-time 3 -fsS -o /dev/null \
    -w "${endpoint}: http=%{http_code} duration=%{time_total}\n" \
    "http://127.0.0.1:8080/$endpoint" >>"$EVID/http-after.txt" 2>&1 || true
done

attempt_reset
(( CLEAN_OK == 1 )) || failure 'safe reset failed; inspect evidence; unknown state was not removed'
(( CHECK_OK == 1 )) || failure 'L03 worker not confirmed COMPLETED; see check-last.json'
note 'REAL_L03_CONTROLLED_PASS: workload/check/cleanup passed; I/O contention remains evidence-dependent.'
exit 0
