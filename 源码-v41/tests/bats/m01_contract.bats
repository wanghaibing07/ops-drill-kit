#!/usr/bin/env bats
# Destructive integration test: only run deliberately inside guarded VMware lab.
setup_file() {
  if [ "${M01_ALLOW_INTEGRATION:-}" != "YES" ]; then
    skip "Set M01_ALLOW_INTEGRATION=YES explicitly in the VM"
  fi
  [ "$(id -u)" -eq 0 ] || skip "Run via sudo"
  [ "$(systemd-detect-virt)" = vmware ] || skip "Not VMware"
}

setup() {
  ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  if [ "${M01_ALLOW_INTEGRATION:-}" != "YES" ]; then
    skip "Integration tests not enabled"
  fi
  [ "$(id -u)" -eq 0 ] || skip "Run via sudo"
  [ "$(systemd-detect-virt)" = vmware ] || skip "Not VMware"
  run bash "$ROOT/drills/mysql/M01/reset.sh"
  [ "$status" -eq 0 ]
}

teardown() {
  if [ "${M01_ALLOW_INTEGRATION:-}" = YES ] && [ "$(id -u)" -eq 0 ]; then
    bash "$ROOT/drills/mysql/M01/reset.sh" >/dev/null 2>&1 || true
  fi
}

@test "initial check succeeds" {
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 0 ]
}

@test "inject => check fails => solution => check passes" {
  run bash "$ROOT/drills/mysql/M01/inject.sh"
  [ "$status" -eq 0 ]
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 1 ]
  run bash "$ROOT/tests/solutions/M01/solution.sh"
  [ "$status" -eq 0 ]
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 0 ]
}

@test "reset is idempotent" {
  run bash "$ROOT/drills/mysql/M01/inject.sh"
  [ "$status" -eq 0 ]
  run bash "$ROOT/drills/mysql/M01/reset.sh"
  [ "$status" -eq 0 ]
  run bash "$ROOT/drills/mysql/M01/reset.sh"
  [ "$status" -eq 0 ]
}

@test "dry run does not change the index" {
  run bash "$ROOT/drills/mysql/M01/inject.sh" --dry-run
  [ "$status" -eq 0 ]
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 0 ]
}

@test "concurrent action refuses shared lock" {
  # Hold project lock in separate process, then exercise the normal entrypoint.
  flock -x /var/lib/opsdrill/m01/m01.lock sleep 3 &
  locker=$!
  sleep 0.3
  run bash "$ROOT/drills/mysql/M01/inject.sh"
  wait "$locker"
  [ "$status" -eq 3 ]
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 0 ]
}

@test "simulated non-VM environment refuses without SQL" {
  fake="$(mktemp -d)"
  printf '#!/bin/sh\necho kvm\n' > "$fake/systemd-detect-virt"
  chmod 700 "$fake/systemd-detect-virt"
  run env PATH="$fake:$PATH" bash "$ROOT/drills/mysql/M01/inject.sh"
  rm -f "$fake/systemd-detect-virt"
  rmdir "$fake"
  [ "$status" -eq 3 ]
  run bash "$ROOT/drills/mysql/M01/check.sh"
  [ "$status" -eq 0 ]
}
