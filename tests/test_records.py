"""Schema (contract) tests for EmailRecord. See docs/decisions/0001-label-taxonomy.md."""

# Fixture records are invented examples for schema tests, not real dataset entries.
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from phishdesk_analysis.records import (
    Category,
    EmailRecord,
    RecordFileError,
    load_records,
    needs_review,
)

FIXTURES = Path(__file__).parent / "fixtures" / "records"


def valid_dicts():
    return [
        json.loads(line)
        for line in (FIXTURES / "valid.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def invalid_dicts():
    return [
        json.loads(line)
        for line in (FIXTURES / "invalid.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_all_valid_examples_load():
    records = load_records(FIXTURES / "valid.jsonl")
    assert len(records) == 12


def test_valid_examples_cover_every_category():
    categories = {r.category for r in load_records(FIXTURES / "valid.jsonl")}
    assert categories == set(Category)


@pytest.mark.parametrize("data", invalid_dicts(), ids=lambda d: d["id"])
def test_invalid_examples_are_rejected(data):
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(data)


def test_duplicate_ids_are_rejected():
    with pytest.raises(RecordFileError, match="duplicate id"):
        load_records(FIXTURES / "duplicate_ids.jsonl")


def test_empty_category_is_rejected_not_treated_as_benign():
    data = valid_dicts()[0] | {"category": ""}
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(data)


def test_missing_category_is_rejected():
    data = valid_dicts()[0]
    del data["category"]
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(data)


def test_unknown_tactic_is_rejected():
    data = valid_dicts()[0] | {"tactics": ["fear"]}
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(data)


def test_tactics_are_optional():
    data = valid_dicts()[0]
    del data["tactics"]
    assert EmailRecord.model_validate(data).tactics == []


def test_unknown_field_is_rejected():
    data = valid_dicts()[0] | {"verdict": "Dangerous"}
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(data)


def test_low_confidence_is_accepted_and_flagged_for_review():
    records = load_records(FIXTURES / "valid.jsonl")
    flagged = needs_review(records)
    assert [r.id for r in flagged] == ["example-nazario-0002"]


def test_bad_line_error_names_the_line(tmp_path):
    bad = tmp_path / "bad.jsonl"
    lines = (FIXTURES / "valid.jsonl").read_text(encoding="utf-8").splitlines()[:2] + ["{not json"]
    bad.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(RecordFileError, match="line 3"):
        load_records(bad)
