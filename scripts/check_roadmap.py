"""Validate the source plan, phase coverage and acyclic prerequisites."""

import json
from pathlib import Path

plan = json.loads((Path(__file__).resolve().parents[1] / "docs/planning/roadmap.json").read_text())
tasks = {t["key"]: t for t in plan["tasks"]}
assert len(tasks) == len(plan["tasks"]), "Duplicate task keys"

# The v2 plan is the agreed baseline and stays at 96 tasks. Anything added since
# carries a different source string, so a silent edit to the baseline still fails.
baseline = [t for t in tasks.values() if t["source"].startswith("PhishDesk Revised 8-Month Plan")]
added = [t for t in tasks.values() if t not in baseline]
assert len(baseline) == 96, f"v2 baseline must stay at 96 tasks, found {len(baseline)}"

assert {t["month"] for t in tasks.values()} == set(range(1, 9))
assert all(t["lead"] != t["reviewer"] and t["acceptance"] for t in tasks.values())
assert all(not any(k in t for k in ("start_date", "due_date")) for t in tasks.values())


def visit(key, ancestors):
    assert key not in ancestors, f"Dependency cycle at {key}"
    for dependency in tasks[key]["dependencies"]:
        assert dependency in tasks, f"Missing prerequisite {dependency}"
        visit(dependency, ancestors | {key})


for key in tasks:
    visit(key, set())

# A prerequisite must not sit in a later phase than the task that needs it.
for key, task in tasks.items():
    for dependency in task["dependencies"]:
        assert tasks[dependency]["month"] <= task["month"], (
            f"{key} (M{task['month']}) depends on {dependency} "
            f"(M{tasks[dependency]['month']}), which is scheduled later"
        )

print(
    f"{len(tasks)} undated tasks ({len(baseline)} v2 baseline, {len(added)} added); "
    "all eight phases; cross-review, phase order and dependency graph valid"
)
