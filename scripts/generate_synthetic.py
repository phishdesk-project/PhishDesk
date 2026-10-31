"""Generate synthetic emails and records from data/generator/*.json.

Usage (from the repo root):
  python scripts/generate_synthetic.py --per-family 5
  python scripts/generate_synthetic.py --count credential=60 --count benign=45

Writes data/raw/synthetic/syn-*.eml and data/processed/synthetic.jsonl.
Held-back families are skipped unless --include-held-back is given (Month 7 only).
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishdesk_analysis.generator import (  # noqa: E402
    GeneratorError,
    load_config,
    plan_by_category,
    plan_per_family,
    write_dataset,
)
from phishdesk_analysis.records import Category  # noqa: E402


def parse_counts(items: list[str]) -> dict[Category, int]:
    counts: dict[Category, int] = {}
    for item in items:
        name, _, number = item.partition("=")
        counts[Category(name)] = int(number)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--per-family", type=int, help="emails per active family")
    group.add_argument("--count", action="append", help="category=N (repeatable)")
    parser.add_argument("--include-held-back", action="store_true", help="Month 7 only")
    args = parser.parse_args()

    try:
        config = load_config(ROOT / "data" / "generator")
        if args.per_family is not None:
            plan = plan_per_family(config, args.per_family, args.include_held_back)
        else:
            plan = plan_by_category(config, parse_counts(args.count), args.include_held_back)
        written = write_dataset(
            config,
            plan,
            ROOT / "data" / "raw" / "synthetic",
            ROOT / "data" / "processed" / "synthetic.jsonl",
        )
    except (GeneratorError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {written} synthetic emails and records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
