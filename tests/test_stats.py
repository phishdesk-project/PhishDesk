"""Tests for the composition report. Records are synthetic and built in memory."""

import datetime as dt
import json

import pytest

from phishdesk_analysis.records import PHISHING_CATEGORIES, Category, EmailRecord, Tactic
from phishdesk_analysis.safety import unreserved_domains
from phishdesk_analysis.stats import composition_report


def rec(i: int, cat: Category, source: str, tactics: list[Tactic] | None = None) -> EmailRecord:
    return EmailRecord(
        id=f"r-{source}-{cat.value.replace('_', '-')}-{i:03d}",
        source=source,
        source_ref="t",
        licence="CC-BY-4.0" if source == "nazario" else "Apache-2.0",
        redistributable=True,
        language="en",
        template_family=f"g{i}",
        is_phishing=cat in PHISHING_CATEGORIES,
        category=cat,
        tactics=tactics or [],
        label_by="person2",
        label_confidence="high",
        raw_path="x",
    )


@pytest.fixture
def data(tmp_path):
    records = [rec(i, c, "synthetic") for c in Category for i in range(10)]
    records += [
        rec(i, Category.CREDENTIAL, "nazario", [Tactic.URGENCY, Tactic.IMPERSONATION])
        for i in range(20)
    ]
    splits: dict[str, object] = {
        "seed": 42,
        "ratios": [0.7, 0.15, 0.15],
        "dropped_duplicates": {"a": "b"},
    }
    ids = [r.id for r in records]
    splits["train"], splits["dev"], splits["test"] = ids[::3], ids[1::3], ids[2::3]
    f = tmp_path / "splits.json"
    f.write_text(json.dumps(splits), encoding="utf-8")
    return records, splits, {"data/splits/splits-v0.json": f}


def test_report_counts(data):
    records, splits, files = data
    report, _ = composition_report(records, splits, files, "0.1", dt.date(2026, 11, 21))
    assert "Records: **80** (20 real, 60 synthetic)" in report
    assert "Exact duplicates dropped before splitting: 1" in report
    assert "| credential |" in report and "2026-11-21" in report
    assert "| urgency | 20 | 20 | 0 |" in report  # 20 phishing urgency tags, all real


def test_report_warns_about_thin_real_categories(data):
    records, splits, files = data
    _, warnings = composition_report(records, splits, files, "0.1", dt.date(2026, 11, 21))
    assert any(w.startswith("payment: only 0 real emails") for w in warnings)
    assert not any(w.startswith("credential: only") for w in warnings)


def test_report_has_no_ids_or_domains(data):
    records, splits, files = data
    report, _ = composition_report(records, splits, files, "0.1", dt.date(2026, 11, 21))
    assert "r-synthetic" not in report and "r-nazario" not in report
    assert unreserved_domains(report) == []


def test_record_missing_from_splits_is_an_error(data):
    records, splits, files = data
    splits["test"] = []
    with pytest.raises(ValueError, match="not in any split"):
        composition_report(records, splits, files, "0.1", dt.date(2026, 11, 21))
