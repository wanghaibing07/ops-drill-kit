#!/usr/bin/env bats

PROJECT="/opt/ops-drill-kit"
ENTRY="$PROJECT/scripts/bootstrap_m02_writer.sh"

@test "Python source compiles" {
  run "$PROJECT/.venv/bin/python" -m py_compile \
    "$PROJECT/scripts/bootstrap_m02_writer.py"
  [ "$status" -eq 0 ]
}

@test "shell entry passes syntax check" {
  run bash -n "$ENTRY"
  [ "$status" -eq 0 ]
}

@test "status is readable before account creation" {
  run sudo bash "$ENTRY" status
  [ "$status" -eq 0 ]
  [[ "$output" == *"pending_state:"* ]]
}

@test "dry-run proves same-session sql_log_bin privilege and restoration" {
  if sudo bash "$ENTRY" status | grep -q "account_exists: yes"; then skip "dry-run requires absent account"; fi
  before=$(sudo mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf \
    -Nse "SELECT @@GLOBAL.log_bin,@@GLOBAL.gtid_mode")
  run sudo bash "$ENTRY" create --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"DRY-RUN PASS"* ]]
  after=$(sudo mysql --defaults-extra-file=/etc/opsdrill/mysql-admin.cnf \
    -Nse "SELECT @@GLOBAL.log_bin,@@GLOBAL.gtid_mode")
  [ "$before" = "$after" ]
}

@test "verify confirms exact writer grants after creation" {
  if sudo bash "$ENTRY" status | grep -q "account_exists: no"; then skip "verify requires existing account"; fi
  run sudo bash "$ENTRY" verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"PASS: exact least-privilege grants"* ]]
}
