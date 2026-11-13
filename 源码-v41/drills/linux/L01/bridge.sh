#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
if (( $# < 2 )); then echo 'L01: action and variant required' >&2; exit 2; fi
action=$1
variant=$2
shift 2
case "$action" in inject|check|reset) ;; *) echo 'L01: invalid action' >&2; exit 2 ;; esac
case "$variant" in
  inode) controller="$ROOT/drills/linux/L01/l01_control.py" ;;
  deleted-open) controller="$ROOT/drills/linux/L01/l01_deleted.py" ;;
  *) echo 'L01: invalid variant' >&2; exit 2 ;;
esac
if [[ "$action" == inject ]]; then
  if (( $# != 0 )); then exit 2; fi
  exec /usr/bin/python3 "$controller" inject --cli
fi
exec /usr/bin/python3 "$controller" "$action" "$@"
