#!/usr/bin/env bash
# Mutates only the lab topology; run only in an explicitly authorized isolated VM.
set -Eeuo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cli="$project/bin/opsdrill"
controller=/usr/local/libexec/opsdrill/n01/n01.py
[[ ${EUID} -eq 0 ]] || { echo 'root required' >&2; exit 2; }
/usr/bin/python3 "$controller" inspect-clean
receipt=$("$cli" start N01)
rid=$(printf '%s' "$receipt" | /usr/bin/python3 -c 'import json,re,sys; x=json.load(sys.stdin); assert set(x)=={"receipt","run_id"} and x["receipt"]=="N01_OWNER_V1" and re.fullmatch("[0-9a-f]{24}", x["run_id"]); print(x["run_id"])')
trap 'echo "N01 contract interrupted; inspect run ${rid} before cleanup" >&2' ERR
attempt=$(/usr/bin/python3 -c 'import json,sys; s=json.load(open("/var/lib/opsdrill/cli/N01.json")); assert s["run_id"]==sys.argv[1] and s["phase"]=="ACTIVE"; print(s["attempt_id"])' "$rid")
/usr/bin/python3 "$controller" verify-owner "$rid"
if "$cli" check N01 --expect-run-id "$rid"; then rc=0; else rc=$?; fi
[[ $rc == 1 ]] || { echo "expected fault check=1, got $rc" >&2; exit 1; }
# Choose an ID with no existing controller completion receipt.
unknown=$(/usr/bin/python3 -c 'import os,secrets; root="/run/opsdrill-n01"; x=secrets.token_hex(12); assert not os.path.lexists(os.path.join(root,"completed-"+x+".json")); print(x)')
if "$cli" reset N01 --expect-run-id "$unknown"; then echo 'unknown active run accepted' >&2; exit 1; fi
/usr/bin/python3 "$controller" verify-owner "$rid"
"$cli" resolve N01 --expect-run-id "$rid"
"$cli" check N01 --expect-run-id "$rid"
"$cli" reset N01 --expect-run-id "$rid"
"$cli" reset N01 --expect-run-id "$rid"
if "$cli" reset N01 --expect-run-id "$unknown"; then echo 'unknown completed run accepted' >&2; exit 1; fi
/usr/bin/python3 "$controller" inspect-clean
# Use the target project's actual report parser on this attempt alone.
/usr/bin/python3 -B - "$project/scripts/report.py" "$attempt" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('report_contract', sys.argv[1])
report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)
with open('/var/lib/opsdrill/events.jsonl', encoding='utf-8') as f:
    rows = [line for line in f if json.loads(line).get('attempt_id') == sys.argv[2]]
assert rows, 'attempt has no events'
assert {json.loads(line)['event'] for line in rows} <= {'inject','diagnosis','check','hint','reset'}
summary = report.summarize(rows)
assert summary['invalid_lines'] == 0 and len(summary['attempts']) == 1
assert summary['attempts'][0]['status'] == 'PASS'
PY
trap - ERR
echo "N01 CLI contract completed for $rid"
