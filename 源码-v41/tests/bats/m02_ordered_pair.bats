#!/usr/bin/env bats

setup() {
  ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  [ "$(id -u)" -eq 0 ] || skip "requires root in lab"
  [ "$(systemd-detect-virt --vm)" = vmware ] || skip "requires VMware"
}

@test "recover is idempotent with no pending state" {
  run bash "$ROOT/scripts/m02_ordered_pair.sh" recover
  [ "$status" -eq 0 ]
  run bash "$ROOT/scripts/m02_ordered_pair.sh" recover
  [ "$status" -eq 0 ]
}

@test "non VMware environment is refused" {
  fake="$BATS_TEST_TMPDIR/bin"
  mkdir "$fake"
  printf '#!/bin/sh\necho kvm\n' > "$fake/systemd-detect-virt"
  chmod 700 "$fake/systemd-detect-virt"
  run env PATH="$fake:$PATH" bash "$ROOT/scripts/m02_ordered_pair.sh" recover
  [ "$status" -ne 0 ]
}

@test "shared M02 lock rejects concurrent operation" {
  ready="$BATS_TEST_TMPDIR/ready"
  flock -x /run/lock/opsdrill-m02-deadlock.lock sh -c 'touch "$1"; sleep 3' sh "$ready" &
  locker=$!
  for _ in {1..30}; do [ -e "$ready" ] && break; sleep 0.1; done
  [ -e "$ready" ]
  run bash "$ROOT/scripts/m02_ordered_pair.sh" recover
  result=$status
  wait "$locker"
  [ "$result" -ne 0 ]
}
