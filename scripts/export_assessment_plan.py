#!/usr/bin/env python3
"""Export FIREWATCH's declared assessment catalog to JSON, CSV, and Markdown."""
from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.assessment_catalog import get_assessment_plan  # noqa: E402

OUT = ROOT / "docs"
PLAN = get_assessment_plan()

(OUT / "assessment-plan-v5.json").write_text(
    json.dumps(PLAN, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)

fields = ["id", "category", "title", "execution_mode", "status_semantics", "standard_mapping", "safe_by_default"]
with (OUT / "assessment-plan-v5.csv").open("w", newline="", encoding="utf-8-sig") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(PLAN["test_cases"])

labels = {
    "automated_passive": "Automated passive/low-impact observation",
    "automated_review_candidate": "Automated signal; validation required",
    "manual_or_test-account_required": "Manual workflow or dedicated test account required",
    "optional_specialist_tool_required": "Specialist tool or dedicated testing required",
}
lines = [
    "# FIREWATCH v5 Assessment Catalog",
    "",
    f"Version: `{PLAN['version']}` · Cases: **{PLAN['total_cases']}**",
    "",
    "This is a coverage plan, not a claim that each entry is automatically executed. Read the execution mode for every item.",
    "",
    "## Standards baseline",
    "",
]
for key, value in PLAN["standards"].items():
    lines.append(f"- `{key}`: {value}")
lines += ["", "## Execution mode totals", ""]
for key, count in PLAN["execution_mode_counts"].items():
    lines.append(f"- **{labels.get(key, key)}:** {count}")
lines += ["", "## Full assessment plan", "", "| ID | Category | Test | Execution mode | Standard mapping |", "|---|---|---|---|---|"]
for row in PLAN["test_cases"]:
    title = row["title"].replace("|", "\\|")
    lines.append(f"| `{row['id']}` | {row['category']} | {title} | `{row['execution_mode']}` | {row['standard_mapping']} |")
lines += ["", "## Important interpretation", "", PLAN["disclaimer"], ""]
(OUT / "ASSESSMENT_CATALOG.md").write_text("\n".join(lines), encoding="utf-8")
print(f"Exported {PLAN['total_cases']} assessment cases: {PLAN['execution_mode_counts']}")
print("Wrote docs/assessment-plan-v5.json, docs/assessment-plan-v5.csv and docs/ASSESSMENT_CATALOG.md")
