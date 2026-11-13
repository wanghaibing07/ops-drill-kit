#!/usr/bin/env bats
# Offline wrapper and ownership-gate checks. No injection, no sudo, no systemctl.
setup() {
  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd -P)"
}

@test "L03 wrappers pass bash -n" {
  for x in inject check reset; do
    run bash -n "$PROJECT_ROOT/drills/linux/L03/$x.sh"
    [ "$status" -eq 0 ]
  done
}

@test "fasttrack passes bash -n" {
  run bash -n "$PROJECT_ROOT/scripts/fasttrack_l03.sh"
  [ "$status" -eq 0 ]
}

@test "L03 controller and receipt parser compile without execution" {
  run /usr/bin/python3 -c 'import ast,sys; [ast.parse(open(p,encoding="utf-8").read()) for p in sys.argv[1:]]' \
    "$PROJECT_ROOT/drills/linux/L03/l03_control.py" "$PROJECT_ROOT/scripts/l03_fasttrack_guard.py"
  [ "$status" -eq 0 ]
}

@test "automatic reset is gated by validated ownership fields" {
  grep -Fq 'if [[ -n "$OWNED_RUN_ID" && -n "$OWNED_UNIT"' "$PROJECT_ROOT/scripts/fasttrack_l03.sh"
  grep -Fq 'verify-owner "$rid" "$unit"' "$PROJECT_ROOT/scripts/fasttrack_l03.sh"
  grep -Fq 'reset.sh" \' "$PROJECT_ROOT/scripts/fasttrack_l03.sh"
  ! grep -q 'START_ATTEMPTED=1' "$PROJECT_ROOT/scripts/fasttrack_l03.sh"
}
