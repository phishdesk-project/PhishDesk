"""Compare two people's labels on the same emails.

Usage:
  python scripts/label_agreement.py data/labels/nazario.csv \
      data/labels/work/review-person1-nazario.csv
  ... --show   # also list the ids where the two labels differ

Accepts committed labels files and work sheets. Only ids labelled in both are compared.
"""

import argparse
import csv

import _common  # noqa: F401  (adds src/ to the path)

from phishdesk_analysis.corpus import disagreements, label_agreement


def read(path: str) -> dict[str, dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["id"]: r for r in csv.DictReader(f) if (r.get("category") or "").strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("first")
    parser.add_argument("second")
    parser.add_argument("--show", action="store_true", help="list differing ids")
    args = parser.parse_args()
    a, b = read(args.first), read(args.second)
    result = label_agreement(a, b)
    print(f"Emails compared: {int(result['shared'])}")
    for key in ("is_phishing", "category", "tactics", "full_match"):
        print(f"{key:<16}{result[key]:.1%}")
    print(f"{'category kappa':<16}{result['category_kappa']:.2f}")
    if args.show:
        diff = disagreements(a, b)
        print(f"\nDifferences ({len(diff)}): id | first | second")
        for msg_id, first, second in diff:
            print(f"  {msg_id} | {first} | {second}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
