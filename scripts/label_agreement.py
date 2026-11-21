"""Compare two people's labels on the same emails.

Usage: python scripts/label_agreement.py data/labels/work/a.csv data/labels/work/b.csv
Only rows labelled in both files (non-empty category) are compared.
"""

import argparse
import csv

import _common  # noqa: F401  (adds src/ to the path)

from phishdesk_analysis.corpus import label_agreement


def read(path: str) -> dict[str, dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["id"]: r for r in csv.DictReader(f) if (r.get("category") or "").strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("first")
    parser.add_argument("second")
    args = parser.parse_args()
    result = label_agreement(read(args.first), read(args.second))
    print(f"Emails compared: {int(result['shared'])}")
    for key in ("is_phishing", "category", "tactics", "full_match"):
        print(f"{key:<16}{result[key]:.1%}")
    print(f"{'category kappa':<16}{result['category_kappa']:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
