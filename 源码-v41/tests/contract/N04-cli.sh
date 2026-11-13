#!/usr/bin/env bash
# Mutating integration contract: execute only in an explicitly authorized isolated lab VM.
set -Eeuo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cli="$project/bin/opsdrill"
[[ ${EUID} -eq 0 ]] || { echo 'root required' >&2; exit 2; }
rid='<unknown>'
trap 'echo "N04 contract interrupted; inspect protected CLI state and run ${rid}; do not guess ownership" >&2' ERR
if receipt=$("$cli" start N04 --actor agent); then start_rc=0; else start_rc=$?; fi
# No parseable receipt means there is no safe ID to reset here; inspect CLI state.
if ! parsed=$(printf '%s' "$receipt" | /usr/bin/python3 -c '
import json,re,sys

def unique(pairs):
    out={}
    for key,value in pairs:
        if key in out: raise ValueError("duplicate key")
        out[key]=value
    return out
x=json.load(sys.stdin,object_pairs_hook=unique)
assert isinstance(x,dict) and set(x)=={"receipt","run_id","initial"}
assert x["receipt"] in ("N04_OWNER_V1","N04_OWNER_V2")
assert isinstance(x["run_id"],str) and re.fullmatch("[0-9a-f]{24}",x["run_id"])
assert isinstance(x["initial"],dict) and x["initial"].get("event")=="injected" and type(x["initial"].get("fault_proven")) is bool
print(x["run_id"],"recovery-v2" if x["receipt"]=="N04_OWNER_V2" else "legacy")'); then
    echo "N04 start has no valid receipt (rc=$start_rc); inspect protected CLI state; no reset attempted" >&2
    exit 2
fi
read -r rid version <<< "$parsed"
# Receipt alone does not prove the CLI saved or owns this ID and version.
attempt=$(/usr/bin/python3 -c '
import json,sys
x=json.load(open("/var/lib/opsdrill/cli/N04.json",encoding="utf-8"))
assert x["drill_id"]=="N04" and x["run_id"]==sys.argv[1]
assert x["phase"] in ("ACTIVE","NEEDS_RESET")
assert (x.get("n04_version")=="recovery-v2" if sys.argv[2]=="recovery-v2" else "n04_version" not in x)
assert isinstance(x["attempt_id"],str)
print(x["attempt_id"])' "$rid" "$version")
if [[ $start_rc -ne 0 ]]; then
    echo "N04 start did not prove a fault (rc=$start_rc); resetting same recorded run" >&2
    "$cli" reset N04 --expect-run-id "$rid" --actor agent
    exit 2
fi
# Ensure successful start really reached ACTIVE before fault checks.
/usr/bin/python3 -c 'import json; assert json.load(open("/var/lib/opsdrill/cli/N04.json",encoding="utf-8"))["phase"]=="ACTIVE"'
unknown=$(/usr/bin/python3 -c 'import os,secrets; roots=("/run/opsdrill-n04","/run/opsdrill-n04-recovery-v2"); x=secrets.token_hex(12); assert all(not os.path.lexists(os.path.join(r,x)) for r in roots); print(x)')
if "$cli" reset N04 --expect-run-id "$unknown" --actor agent; then echo 'unknown active run accepted' >&2; exit 1; fi
if "$cli" check N04 --expect-run-id "$rid" --actor agent; then rc=0; else rc=$?; fi
if [[ $rc -ne 1 ]]; then
    echo "N04 fault not proven (check=$rc); stopping owned run; contract inconclusive" >&2
    "$cli" reset N04 --expect-run-id "$rid" --actor agent
    exit 2
fi
"$cli" resolve N04 --expect-run-id "$rid" --actor agent
"$cli" check N04 --expect-run-id "$rid" --actor agent
"$cli" reset N04 --expect-run-id "$rid" --actor agent
# Once state has been removed, select v2 explicitly; default remains legacy.
repeat_args=()
if [[ $version == recovery-v2 ]]; then repeat_args=(--n04-version recovery-v2); fi
repeat=$("$cli" reset N04 --expect-run-id "$rid" "${repeat_args[@]}" --actor agent)
printf '%s' "$repeat" | /usr/bin/python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x.get("run_id")==sys.argv[1] and x.get("action")=="reset" and x.get("ok") is True
assert x.get("service_stopped") is True and x.get("already_completed") is True' "$rid"
if "$cli" reset N04 --expect-run-id "$unknown" --actor agent; then echo 'unknown legacy completed run accepted' >&2; exit 1; fi
if [[ $version == recovery-v2 ]] && "$cli" reset N04 --expect-run-id "$unknown" --n04-version recovery-v2 --actor agent; then echo 'unknown v2 completed run accepted' >&2; exit 1; fi
# Optional, supplied existing old completion: default routing must still reach legacy.
if [[ -n ${N04_LEGACY_COMPLETED_ID:-} ]]; then
    [[ $N04_LEGACY_COMPLETED_ID =~ ^[0-9a-f]{24}$ && $N04_LEGACY_COMPLETED_ID != "$rid" ]] || { echo 'invalid historical legacy ID' >&2; exit 2; }
    legacy=$("$cli" reset N04 --expect-run-id "$N04_LEGACY_COMPLETED_ID" --actor agent)
    printf '%s' "$legacy" | /usr/bin/python3 -c 'import json,sys; x=json.load(sys.stdin); assert x.get("run_id")==sys.argv[1] and x.get("action")=="reset" and x.get("ok") is True and x.get("service_stopped") is True and x.get("already_completed") is True' "$N04_LEGACY_COMPLETED_ID"
else
    echo 'N04 historical legacy receipt compatibility: SKIPPED (no historical ID supplied)' >&2
fi
# Validate using the target project's real report parser, if present.
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
echo "N04 CLI contract completed for $rid ($version)"
