"""Create double-labelling sheets for a second labeller.

Usage (run by the second labeller, after downloading and preparing the sources):
  python scripts/make_review_sheet.py --by person1

Picks a seeded random ~15% of the committed real labels per source, writes the ids to
data/labels/review-sample.json (committable: ids only) and creates blank sheets
data/labels/work/review-<by>-<source>.csv that show none of the first labeller's answers.
"""

import argparse
import json

from _common import LABELS_DIR, RAW_PUBLIC, WORK_DIR

from phishdesk_analysis.corpus import make_label_sheet, review_sample


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--by", required=True, help="second labeller's name, e.g. person1")
    parser.add_argument("--fraction", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--force", action="store_true", help="overwrite existing review sheets")
    args = parser.parse_args()

    sample = review_sample(LABELS_DIR, args.fraction, args.seed)
    if not sample:
        print("ERROR: no committed labels found in data/labels/")
        return 1
    record = {"fraction": args.fraction, "seed": args.seed, "ids": sample}
    (LABELS_DIR / "review-sample.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    for source, ids in sample.items():
        src_dir = RAW_PUBLIC / source
        if not (src_dir / "index.csv").exists():
            print(f"ERROR: {source} is not prepared on this machine; see data/README.md")
            return 1
        out = WORK_DIR / f"review-{args.by}-{source}.csv"
        if out.exists() and not args.force:
            print(f"{out.name} already exists (kept). Use --force to recreate it.")
            continue
        missing = set(ids) - set(
            line.split(",")[0] for line in (src_dir / "index.csv").read_text("utf-8").splitlines()
        )
        if missing:
            print(
                f"ERROR: {len(missing)} {source} ids not found locally, e.g. {sorted(missing)[:3]}"
            )
            print("Prepare the source with the same commands and parameters as data/README.md.")
            return 1
        n = make_label_sheet(src_dir / "index.csv", src_dir / "emails", out, only_ids=set(ids))
        print(f"{out.name}: {n} emails to label")
    print("Label with: python scripts/label_cli.py review-<by>-<source> --by <by>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
