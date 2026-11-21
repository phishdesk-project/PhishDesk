"""Create a local labelling sheet (CSV) for one source.

Usage:
  python scripts/make_label_sheet.py nazario
  python scripts/make_label_sheet.py spamassassin --sample 150
  python scripts/make_label_sheet.py enron --bucket urgent

Output: data/labels/work/<name>.csv (gitignored: it contains real senders and subjects).
Import it into Google Sheets, label, then download it back as CSV to the same path.
"""

import argparse
import json

from _common import RAW_PUBLIC, WORK_DIR

from phishdesk_analysis.corpus import make_label_sheet

PREFILL = {"nazario": "true", "spamassassin": "false", "enron": "false"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", choices=sorted(PREFILL))
    parser.add_argument("--sample", type=int, help="random sample size (fixed seed)")
    parser.add_argument("--bucket", choices=["urgent", "other"], help="Enron only")
    parser.add_argument("--force", action="store_true", help="overwrite an existing sheet")
    args = parser.parse_args()

    src_dir = RAW_PUBLIC / args.source
    if not (src_dir / "index.csv").exists():
        print(f"ERROR: no index for {args.source}; run prepare_sources.py or find_enron.py")
        return 1
    only = None
    name = args.source
    if args.bucket:
        candidates = json.loads((src_dir / "candidates.json").read_text("utf-8"))
        only = set(candidates[args.bucket])
        name = f"{args.source}-{args.bucket}"
    out = WORK_DIR / f"{name}.csv"
    if out.exists() and not args.force:
        print(f"ERROR: {out} already exists and may hold your labels. Use --force to overwrite.")
        return 1
    count = make_label_sheet(
        src_dir / "index.csv",
        src_dir / "emails",
        out,
        prefill_is_phishing=PREFILL[args.source],
        sample=args.sample,
        only_ids=only,
    )
    print(f"Wrote {count} rows to {out}  (do not commit this file)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
