"""EmailRecord: the validated format for one labeled email in the PhishDesk dataset.

Label rules come from docs/decisions/0001-label-taxonomy.md.
"""

from __future__ import annotations

import datetime as dt
import json
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# Keep in sync with data/SOURCES.md. Only approved sources belong here.
KNOWN_SOURCES = {"synthetic", "nazario", "spamassassin", "enron"}


class Category(StrEnum):
    CREDENTIAL = "credential"
    PAYMENT = "payment"
    IMPERSONATION = "impersonation"
    URGENCY = "urgency"
    BENIGN = "benign"
    LEGIT_URGENT = "legit_urgent"


PHISHING_CATEGORIES = {
    Category.CREDENTIAL,
    Category.PAYMENT,
    Category.IMPERSONATION,
    Category.URGENCY,
}


class Tactic(StrEnum):
    URGENCY = "urgency"
    IMPERSONATION = "impersonation"
    LINK_LURE = "link_lure"
    ATTACHMENT_LURE = "attachment_lure"
    QR_CODE = "qr_code"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EmailRecord(BaseModel):
    """One labeled email. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    source: str
    source_ref: str = Field(min_length=1)
    licence: str = Field(min_length=1)
    redistributable: bool
    language: str = Field(pattern=r"^[a-z]{2}$")  # ISO 639-1, e.g. "en"
    date: dt.date | None = None  # some public emails have no usable Date header
    template_family: str = Field(min_length=1)
    is_phishing: bool
    category: Category
    tactics: list[Tactic] = Field(default_factory=list)  # optional detail
    label_by: str = Field(min_length=1)
    label_confidence: Confidence
    raw_path: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_consistency(self) -> EmailRecord:
        if self.source not in KNOWN_SOURCES:
            raise ValueError(
                f"unknown source '{self.source}': add it to data/SOURCES.md and KNOWN_SOURCES first"
            )
        if self.is_phishing and self.category not in PHISHING_CATEGORIES:
            raise ValueError(
                f"is_phishing is true but category '{self.category.value}' is a legitimate category"
            )
        if not self.is_phishing and self.category in PHISHING_CATEGORIES:
            raise ValueError(
                f"is_phishing is false but category '{self.category.value}' is a phishing category"
            )
        if len(set(self.tactics)) != len(self.tactics):
            raise ValueError("tactics contains duplicates")
        return self


class RecordFileError(ValueError):
    """Raised when a JSONL file contains an invalid record or duplicate IDs."""


def load_records(path: str | Path) -> list[EmailRecord]:
    """Read a JSONL file and validate every record. Fails on the first problem, naming the line."""
    records: list[EmailRecord] = []
    seen: dict[str, int] = {}
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                record = EmailRecord.model_validate(json.loads(line))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise RecordFileError(f"{path}, line {line_no}: {exc}") from exc
            if record.id in seen:
                raise RecordFileError(
                    f"{path}, line {line_no}: duplicate id '{record.id}' "
                    f"(first on line {seen[record.id]})"
                )
            seen[record.id] = line_no
            records.append(record)
    return records


def needs_review(records: list[EmailRecord]) -> list[EmailRecord]:
    """Records labeled with low confidence, to be checked by the other owner."""
    return [r for r in records if r.label_confidence is Confidence.LOW]
