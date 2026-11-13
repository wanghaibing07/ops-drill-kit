#!/usr/bin/env bats

PROJECT_ROOT="/opt/ops-drill-kit"
ENTRY="$PROJECT_ROOT/scripts/m01_slowlog.sh"

@test "Python syntax and shell syntax are valid" {
  run python3 -m py_compile "$PROJECT_ROOT/scripts/m01_slowlog.py"
  [ "$status" -eq 0 ]
  run bash -n "$ENTRY"
  [ "$status" -eq 0 ]
}

@test "status reports no pending recovery state" {
  run sudo bash "$ENTRY" status
  [ "$status" -eq 0 ]
  [[ "$output" == *"no pending M01 slow-log state"* ]]
}

@test "dry-run validates credentials and baseline without changing global state" {
  before=$(sudo mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf \
    -Nse "SELECT @@GLOBAL.slow_query_log, @@GLOBAL.long_query_time")
  run sudo bash "$ENTRY" capture --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"DRY-RUN PASS"* ]]
  after=$(sudo mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf \
    -Nse "SELECT @@GLOBAL.slow_query_log, @@GLOBAL.long_query_time")
  [ "$before" = "$after" ]
}

@test "unknown action is rejected" {
  run sudo bash "$ENTRY" invalid-action
  [ "$status" -ne 0 ]
}
