"""Write the composition report docs/data/composition.md from the built dataset.

Usage (after build_dataset.py): python scripts/dataset_stats.py
"""

import datetime as dt
import sys

from _common import LABELS_DIR, RECORDS_JSONL, ROOT, SPLITS_JSON, SYNTHETIC_JSONL

from phishdesk_analysis.generator import GENERATOR_VERSION
from phishdesk_analysis.records import load_records
from phishdesk_analysis.stats import composition_report, load_splits

OUT = ROOT / "docs" / "data" / "composition.md"


def main() -> int:
    for path in (RECORDS_JSONL, SPLITS_JSON):
        if not path.exists():
            print(f"ERROR: {path.relative_to(ROOT)} not found; run build_dataset.py first")
            return 1
    hashed = {
        "data/processed/records.jsonl (local)": RECORDS_JSONL,
        "data/processed/synthetic.jsonl (local)": SYNTHETIC_JSONL,
        "data/splits/splits-v0.json": SPLITS_JSON,
    }
    hashed |= {f"data/labels/{p.name}": p for p in sorted(LABELS_DIR.glob("*.csv"))}
    report, warnings = composition_report(
        load_records(RECORDS_JSONL),
        load_splits(SPLITS_JSON),
        {k: v for k, v in hashed.items() if v.exists()},
        GENERATOR_VERSION,
        dt.date.today(),
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(report, encoding="utf-8", newline="\n")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    print(report)
    print(f"Wrote {OUT.relative_to(ROOT)} with {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
