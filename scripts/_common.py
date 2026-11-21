"""Shared paths for the dataset scripts."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

REGISTER = ROOT / "data" / "sources.json"
RAW_PUBLIC = ROOT / "data" / "raw" / "public"
LABELS_DIR = ROOT / "data" / "labels"
WORK_DIR = LABELS_DIR / "work"  # gitignored: contains real senders and subjects
SYNTHETIC_JSONL = ROOT / "data" / "processed" / "synthetic.jsonl"
RECORDS_JSONL = ROOT / "data" / "processed" / "records.jsonl"
SPLITS_JSON = ROOT / "data" / "splits" / "splits-v0.json"
