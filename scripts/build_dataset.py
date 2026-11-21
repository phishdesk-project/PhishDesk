"""Build records.jsonl, remove duplicates and create the group-aware split.

Usage: python scripts/build_dataset.py
Needs: downloaded/prepared public sources, data/labels/*.csv, and
       data/processed/synthetic.jsonl (from generate_synthetic.py).
Writes: data/processed/records.jsonl (gitignored) and data/splits/splits-v0.json (committed).
"""

import argparse
import json
from collections import Counter

from _common import (
    LABELS_DIR,
    RAW_PUBLIC,
    RECORDS_JSONL,
    REGISTER,
    ROOT,
    SPLITS_JSON,
    SYNTHETIC_JSONL,
)

from phishdesk_analysis.corpus import (
    CorpusError,
    build_records,
    dedupe,
    parse_email,
    plain_text,
    split_records,
    write_splits,
)
from phishdesk_analysis.sources import load_register


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--near", type=float, default=0.9, help="near-duplicate threshold")
    args = parser.parse_args()
    try:
        records, paths = build_records(
            load_register(REGISTER), RAW_PUBLIC, LABELS_DIR, SYNTHETIC_JSONL, ROOT
        )
    except CorpusError as exc:
        print(f"ERROR: {exc}")
        return 1
    texts = {rid: plain_text(parse_email(path.read_bytes())) for rid, path in paths.items()}
    dedup = dedupe(records, texts, args.near)
    kept = [r for r in records if r.id in dedup.groups]
    splits = split_records(kept, dedup.groups, seed=args.seed)

    RECORDS_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with open(RECORDS_JSONL, "w", encoding="utf-8", newline="\n") as out:
        for r in sorted(kept, key=lambda r: r.id):
            out.write(json.dumps(r.model_dump(mode="json")) + "\n")
    write_splits(splits, dedup, SPLITS_JSON, args.seed)

    split_of = {rid: name for name, ids in splits.items() for rid in ids}
    table = Counter((r.category.value, split_of[r.id]) for r in kept)
    real = Counter((r.category.value, split_of[r.id]) for r in kept if r.source != "synthetic")
    print(f"Records: {len(kept)} kept, {len(dedup.dropped)} exact duplicates dropped")
    print("Synthetic records are train-only; dev and test hold real emails.")
    print(f"{'category':<15}{'train (real)':>14}{'dev':>7}{'test':>7}")
    for cat in sorted({c for c, _ in table}):
        train = f"{table[(cat, 'train')]} ({real[(cat, 'train')]})"
        print(f"{cat:<15}{train:>14}{table[(cat, 'dev')]:>7}{table[(cat, 'test')]:>7}")
    missing = [
        (c, s)
        for c in {c for c, _ in table}
        for s in ("train", "dev", "test")
        if table[(c, s)] == 0
    ]
    if missing:
        print(f"WARNING: empty category/split cells: {sorted(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
