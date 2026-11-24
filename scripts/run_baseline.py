"""Train the TF-IDF + logistic regression baseline and evaluate it.

Usage (from the repo root, after build_dataset.py):
  python scripts/run_baseline.py                       # train on train, evaluate on dev
  python scripts/run_baseline.py --split test --final  # frozen test set: final runs only

Writes results/baseline/<config name>/<split>/: report.md, metrics.json,
manifest.json, false_positives.csv and false_negatives.csv (ids and scores only).
"""

import argparse
import sys
from pathlib import Path

from _common import RECORDS_JSONL, ROOT, SPLITS_JSON

from phishdesk_analysis.baseline import (
    BaselineError,
    load_config,
    make_manifest,
    run_baseline,
    split_ids,
    train_counts,
    write_outputs,
)
from phishdesk_analysis.corpus import parse_email, plain_text
from phishdesk_analysis.records import load_records
from phishdesk_analysis.sources import sha256_of
from phishdesk_analysis.stats import load_splits

DEFAULT_CONFIG = ROOT / "configs" / "baseline-v0.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--split", choices=["dev", "test"], default="dev")
    parser.add_argument(
        "--final", action="store_true", help="required to evaluate on the frozen test split"
    )
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    if args.split == "test" and not args.final:
        print("ERROR: the test split is the frozen evaluation set. Tune on dev; use")
        print("       --split test --final only for an agreed final evaluation.")
        return 1
    for path in (RECORDS_JSONL, SPLITS_JSON):
        if not path.exists():
            print(f"ERROR: {path.relative_to(ROOT)} not found; run build_dataset.py first")
            return 1
    try:
        config = load_config(args.config)
        records = {r.id: r for r in load_records(RECORDS_JSONL)}
        splits = load_splits(SPLITS_JSON)
        needed = split_ids(splits, "train") + split_ids(splits, args.split)
        texts: dict[str, str] = {}
        for rid in needed:
            if rid not in records:
                raise BaselineError(f"split id '{rid}' has no record in records.jsonl")
            path = ROOT / records[rid].raw_path
            if not path.exists():
                raise BaselineError(f"email file missing for {rid}: {records[rid].raw_path}")
            texts[rid] = plain_text(parse_email(path.read_bytes()))
        result = run_baseline(config, records, texts, splits, args.split)
    except (BaselineError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1

    command = "python scripts/run_baseline.py " + " ".join(sys.argv[1:])
    manifest = make_manifest(
        config,
        args.split,
        sha256_of(SPLITS_JSON),
        sha256_of(RECORDS_JSONL),
        ROOT,
        command.strip(),
        {
            "train": len(split_ids(splits, "train")),
            args.split: len(split_ids(splits, args.split)),
            **{
                f"train_{k}": v
                for k, v in train_counts(records, split_ids(splits, "train")).items()
            },
        },
    )
    out_dir = ROOT / "results" / "baseline" / config.name / args.split
    write_outputs(result, out_dir, manifest)
    m = result.metrics
    print(
        f"{config.name} on {args.split}: n={m['n']} precision={m['precision']} "
        f"recall={m['recall']} f1={m['f1']}"
    )
    print(
        f"False positives: {len(result.false_positives)} · "
        f"false negatives: {len(result.false_negatives)}"
    )
    print(f"Wrote {out_dir.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
