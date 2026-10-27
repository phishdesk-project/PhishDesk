"""Validate the source plan, phase coverage and acyclic prerequisites."""

import json
from pathlib import Path

plan = json.loads((Path(__file__).resolve().parents[1] / "docs/planning/roadmap.json").read_text())
tasks = {t["key"]: t for t in plan["tasks"]}
assert len(tasks) == len(plan["tasks"]) == 96
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
print("96 undated tasks; all eight phases; cross-review and dependency graph valid")
