#!/usr/bin/env python3
"""Read-only repository inventory. File presence is never reported as a passed drill."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
paths = ([("linux", f"L{i:02d}") for i in range(1, 5)]
         + [("network", f"N{i:02d}") for i in range(1, 5)]
         + [("mysql", f"M{i:02d}") for i in range(1, 5)]
         + [("capstone", "C01")])
required = ("inject.sh", "check.sh", "reset.sh", "ticket.md", "runbook.md")
report = {"status": "INVENTORY_ONLY_NOT_ACCEPTANCE", "project_root": str(root), "drills": [], "tools": {}}
for domain, code in paths:
    folder = root / "drills" / domain / code
    found = [name for name in required if (folder / name).is_file()]
    missing = [name for name in required if name not in found]
    report["drills"].append({
        "id": code, "folder": str(folder.relative_to(root)),
        "presence": "MISSING" if not folder.is_dir() else ("FILES_PRESENT" if not missing else "PARTIAL"),
        "present_required": found, "missing_required": missing,
        "tested": None,
    })
for path in ("bin/opsdrill", "scripts/triage60.py", "scripts/triage60.sh",
             "tests/unit/test_triage60.py", "scripts/log_radar.sh",
             "scripts/backup_verify.sh", "scripts/netcheck.sh", "sql/mysql_diag.sql",
             "scripts/report.py", ".github/workflows/ci.yml"):
    report["tools"][path] = "PRESENT_UNVERIFIED" if (root / path).is_file() else "MISSING"
json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
print()
