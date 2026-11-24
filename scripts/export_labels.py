"""Turn labelled work sheets into the committed, privacy-safe labels file.

Usage:
  python scripts/export_labels.py nazario
  python scripts/export_labels.py enron        # combines enron*.csv work sheets

Reads data/labels/work/<source>*.csv, validates every labelled row against the
local email's sha256, and writes data/labels/<source>.csv with ids, hashes,
labels and a hashed sender group only.
"""

import argparse

from _common import LABELS_DIR, RAW_PUBLIC, WORK_DIR

from phishdesk_analysis.corpus import CorpusError, export_labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source")
    args = parser.parse_args()
    sheets = sorted(WORK_DIR.glob(f"{args.source}*.csv"))
    if not sheets:
        print(f"ERROR: no work sheets matching data/labels/work/{args.source}*.csv")
        return 1
    src_dir = RAW_PUBLIC / args.source
    try:
        count = export_labels(
            sheets, src_dir / "index.csv", src_dir / "emails", LABELS_DIR / f"{args.source}.csv"
        )
    except CorpusError as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"Exported {count} labels from {len(sheets)} sheet(s) to data/labels/{args.source}.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
