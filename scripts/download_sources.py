"""Download approved public sources into data/raw/public/ and verify their SHA-256.

Usage (from the repo root):
  python scripts/download_sources.py nazario
  python scripts/download_sources.py nazario --record   # first download only: saves hashes
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishdesk_analysis.sources import (  # noqa: E402
    SourceError,
    download_source,
    load_register,
    write_recorded_hashes,
)

REGISTER = ROOT / "data" / "sources.json"
RAW_ROOT = ROOT / "data" / "raw" / "public"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="+", help="source IDs from data/sources.json")
    parser.add_argument("--record", action="store_true", help="save hashes for files with none")
    args = parser.parse_args()

    register = load_register(REGISTER)
    for source_id in args.sources:
        try:
            hashes = download_source(register, source_id, RAW_ROOT, record=args.record)
        except (SourceError, KeyError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        for name, digest in hashes.items():
            print(f"{source_id}/{name}  sha256={digest}")
        if args.record:
            write_recorded_hashes(REGISTER, source_id, hashes)
            print(f"Recorded hashes in {REGISTER.relative_to(ROOT)}: review and commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
