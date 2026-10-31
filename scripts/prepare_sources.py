"""Turn downloaded sources into one .eml per message plus an index.csv (id, file, sha256).

Usage (from the repo root, after download_sources.py):
  python scripts/prepare_sources.py nazario
  python scripts/prepare_sources.py spamassassin

Output stays under data/raw/public/<id>/emails/ (gitignored).
Enron is read directly from its archive in Phase 5, so it needs no preparation.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishdesk_analysis.sources import (  # noqa: E402
    IndexRow,
    SourceError,
    load_register,
    safe_extract_tar,
    sha256_of,
    split_mbox,
    write_index,
)

REGISTER = ROOT / "data" / "sources.json"
RAW_ROOT = ROOT / "data" / "raw" / "public"


def prepare_nazario(names: list[str], src_dir: Path, out_dir: Path) -> list[IndexRow]:
    rows: list[IndexRow] = []
    for name in names:  # e.g. "phishing-2025" -> ids "nazario-2025-0000", ...
        year = name.rsplit("-", 1)[-1]
        rows += split_mbox(src_dir / name, out_dir, prefix=f"nazario-{year}")
    return rows


def prepare_spamassassin(names: list[str], src_dir: Path, out_dir: Path) -> list[IndexRow]:
    rows: list[IndexRow] = []
    for name in names:
        safe_extract_tar(src_dir / name, out_dir)
    for group_dir in sorted(p for p in out_dir.iterdir() if p.is_dir()):
        files = sorted(p for p in group_dir.iterdir() if p.is_file() and p.name != "cmds")
        for i, path in enumerate(files):
            msg_id = f"spamassassin-{group_dir.name.replace('_', '-')}-{i:04d}"
            rows.append((msg_id, f"{group_dir.name}/{path.name}", sha256_of(path)))
    return rows


PREPARERS = {"nazario": prepare_nazario, "spamassassin": prepare_spamassassin}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", choices=sorted(PREPARERS))
    args = parser.parse_args()

    source = load_register(REGISTER).get(args.source)
    src_dir = RAW_ROOT / source.id
    out_dir = src_dir / "emails"
    missing = [f.name for f in source.files if not (src_dir / f.name).exists()]
    if missing:
        print(
            f"ERROR: run download_sources.py {source.id} first (missing: {missing})",
            file=sys.stderr,
        )
        return 1
    try:
        rows = PREPARERS[source.id]([f.name for f in source.files], src_dir, out_dir)
    except SourceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    write_index(rows, src_dir / "index.csv")
    print(f"{source.id}: {len(rows)} emails in {out_dir.relative_to(ROOT)}, index at index.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
