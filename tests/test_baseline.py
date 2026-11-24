"""Tests for the TF-IDF + logistic regression baseline. All data is synthetic."""

import csv
import json
from pathlib import Path

import pytest

from phishdesk_analysis.baseline import (
    BaselineConfig,
    BaselineError,
    compute_metrics,
    load_config,
    make_manifest,
    run_baseline,
    wilson,
    write_outputs,
)
from phishdesk_analysis.corpus import parse_email, plain_text
from phishdesk_analysis.generator import load_config as load_generator
from phishdesk_analysis.generator import plan_per_family, write_dataset
from phishdesk_analysis.records import Category, EmailRecord, load_records
from phishdesk_analysis.safety import unreserved_domains

ROOT = Path(__file__).resolve().parents[1]
CONFIG = BaselineConfig(name="baseline-test", seed=42)


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    """Train on active families; dev/test from held-back families (unseen templates)."""
    tmp = tmp_path_factory.mktemp("baseline")
    generator = load_generator(ROOT / "data" / "generator")
    write_dataset(
        generator,
        plan_per_family(generator, 8, include_held_back=True),
        tmp / "eml",
        tmp / "records.jsonl",
    )
    records = {r.id: r for r in load_records(tmp / "records.jsonl")}
    held = {f.id for f in generator.families if f.held_back}
    splits: dict[str, list[str]] = {"train": [], "dev": [], "test": []}
    for rid, r in sorted(records.items()):
        if r.template_family not in held:
            splits["train"].append(rid)
        else:
            splits["dev" if int(rid[-4:]) % 2 == 0 else "test"].append(rid)
    texts = {
        rid: plain_text(parse_email((tmp / "eml" / f"{rid}.eml").read_bytes())) for rid in records
    }
    return records, texts, splits, tmp


def test_repo_config_is_valid():
    config = load_config(ROOT / "configs" / "baseline-v0.json")
    assert config.seed == 42 and config.name == "baseline-v0"


def test_run_produces_consistent_metrics(data):
    records, texts, splits, _ = data
    result = run_baseline(CONFIG, records, texts, splits, "dev")
    m = result.metrics
    (tn, fp), (fn, tp) = m["confusion_matrix"]["rows_actual_cols_predicted"]
    assert tn + fp + fn + tp == m["n"] == len(splits["dev"])
    assert m["positives"] == tp + fn and m["negatives"] == tn + fp
    for key in ("precision", "recall", "f1", "accuracy"):
        assert m[key] is None or 0.0 <= m[key] <= 1.0
    assert len(result.false_positives) == fp and len(result.false_negatives) == fn
    assert set(m["by_category"]) <= {c.value for c in Category}


def test_runs_are_deterministic(data):
    records, texts, splits, _ = data
    a = run_baseline(CONFIG, records, texts, splits, "dev")
    b = run_baseline(CONFIG, records, texts, splits, "dev")
    assert a.model_dump() == b.model_dump()


def test_learns_something_on_unseen_templates(data):
    records, texts, splits, _ = data
    m = run_baseline(CONFIG, records, texts, splits, "test").metrics
    assert m["accuracy"] is not None and m["accuracy"] > 0.5


def test_overlapping_ids_are_rejected(data):
    records, texts, splits, _ = data
    leaky = dict(splits, dev=splits["dev"] + splits["train"][:1])
    with pytest.raises(BaselineError, match="both train and dev"):
        run_baseline(CONFIG, records, texts, leaky, "dev")


def test_shared_groups_are_rejected(data):
    records, texts, splits, _ = data
    moved = splits["train"][0]
    leaky = dict(splits, train=splits["train"][1:], dev=splits["dev"] + [moved])
    with pytest.raises(BaselineError, match="groups shared"):
        run_baseline(CONFIG, records, texts, leaky, "dev")


def test_unknown_or_empty_split_is_rejected(data):
    records, texts, splits, _ = data
    with pytest.raises(BaselineError, match="empty"):
        run_baseline(CONFIG, records, texts, dict(splits, dev=[]), "dev")
    with pytest.raises(BaselineError, match="not found"):
        run_baseline(CONFIG, records, texts, {"train": splits["train"]}, "dev")


def test_missing_record_or_text_is_rejected(data):
    records, texts, splits, _ = data
    with pytest.raises(BaselineError, match="no record"):
        run_baseline(CONFIG, records, texts, dict(splits, dev=["ghost-0001"]), "dev")
    blank = dict(texts, **{splits["dev"][0]: "   "})
    with pytest.raises(BaselineError, match="no text"):
        run_baseline(CONFIG, records, blank, splits, "dev")


def test_single_class_training_is_rejected(data):
    records, texts, splits, _ = data
    phishing_only = [i for i in splits["train"] if records[i].is_phishing]
    with pytest.raises(BaselineError, match="both phishing and legitimate"):
        run_baseline(CONFIG, records, texts, dict(splits, train=phishing_only), "dev")


def test_invalid_config_is_rejected():
    with pytest.raises(ValueError):
        BaselineConfig(name="Bad Name", seed=1)
    with pytest.raises(ValueError):
        BaselineConfig.model_validate({"name": "x", "seed": 1, "threshold": 1.5})


def record(i: int, phishing: bool) -> EmailRecord:
    return EmailRecord(
        id=f"r-{i:03d}",
        source="synthetic",
        source_ref="t",
        licence="t",
        redistributable=True,
        language="en",
        template_family="g",
        is_phishing=phishing,
        category="credential" if phishing else "benign",
        label_by="t",
        label_confidence="high",
        raw_path="x",
    )


def test_metrics_on_known_case():
    records = [record(0, True), record(1, True), record(2, False), record(3, False)]
    m = compute_metrics(records, [0.9, 0.2, 0.7, 0.1], threshold=0.5)
    assert m["confusion_matrix"]["rows_actual_cols_predicted"] == [[1, 1], [1, 1]]
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["f1"] == 0.5
    assert m["by_category"]["benign"]["false_alarms"] == "1/2"


def test_metrics_with_no_predicted_positives_are_undefined_not_zero():
    m = compute_metrics([record(0, True), record(1, False)], [0.1, 0.1], threshold=0.5)
    assert m["precision"] is None and m["recall"] == 0.0 and m["f1"] is None


def test_wilson_interval():
    low, high = wilson(9, 10)
    assert 0.5 < low < 0.9 < high <= 1.0
    assert wilson(0, 0) is None


def test_outputs_hold_ids_and_numbers_only(data):
    records, texts, splits, tmp = data
    result = run_baseline(CONFIG, records, texts, splits, "dev")
    manifest = make_manifest(CONFIG, "dev", "a" * 64, "b" * 64, ROOT, "test-run", {"train": 1})
    out = tmp / "out"
    write_outputs(result, out, manifest)
    assert {p.name for p in out.iterdir()} == {
        "report.md",
        "metrics.json",
        "manifest.json",
        "false_positives.csv",
        "false_negatives.csv",
    }
    for path in out.iterdir():
        text = path.read_text("utf-8")
        assert unreserved_domains(text) == [], path.name
        assert "@" not in text, path.name
    with open(out / "false_positives.csv", encoding="utf-8") as f:
        assert next(csv.reader(f)) == ["id", "source", "category", "phishing_score"]


def test_manifest_records_seed_split_and_environment():
    manifest = make_manifest(CONFIG, "test", "a" * 64, "b" * 64, ROOT, "cmd", {"train": 1})
    assert manifest["seed"] == 42 and manifest["split"] == "test"
    assert manifest["final_evaluation"] is True
    assert manifest["split_sha256"] == "a" * 64
    env = manifest["environment"]
    assert env["python"] and "scikit-learn" in env["packages"]
    assert "commit" in manifest["git"]
    json.dumps(manifest)
