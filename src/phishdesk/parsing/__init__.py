"""Bounded synthetic MIME -> Evidence v1. No network, rendering or file extraction."""

import json
import math
import subprocess
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from uuid import UUID

from phishdesk.contracts import EvidenceV1


@dataclass(frozen=True)
class ParseLimits:
    """Callers may lower ceilings, never raise them beyond these defaults."""

    message_bytes: int = 2 * 1024 * 1024
    header_bytes: int = 32 * 1024
    header_count: int = 100
    parts: int = 100
    depth: int = 8
    body_bytes: int = 100_000
    part_bytes: int = 512 * 1024
    decoded_bytes: int = 2 * 1024 * 1024
    attachments: int = 20
    links: int = 200
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            ceiling = field.default
            if field.name == "timeout_seconds":
                valid = type(value) in (float, int) and math.isfinite(value)
            else:
                valid = type(value) is int
            if not valid or not 0 < value <= ceiling:
                raise ValueError("Parser limits must be positive and within built-in ceilings")


def _failure(case_id: UUID, state: str) -> EvidenceV1:
    return EvidenceV1(
        case_id=case_id,
        source="synthetic",
        subject="",
        from_address="",
        body_text="",
        missing_evidence=(state, "authentication.not_checked", "sandbox.not_run", "qr.not_run"),
    )


def parse_eml(data: bytes, *, case_id: UUID, limits: ParseLimits | None = None) -> EvidenceV1:
    """Parse synthetic bytes in a killable worker; failures contain static codes only.

    The deadline includes worker startup. Hard byte/operation ceilings bound memory;
    this is not an OS security sandbox. Only a complete worker result is accepted.
    """
    limits = limits or ParseLimits()
    if len(data) > limits.message_bytes:
        return _failure(case_id, "parser.message_bytes")
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "phishdesk.parsing._worker",
                str(case_id),
                json.dumps(asdict(limits)),
            ],
            input=data,
            capture_output=True,
            timeout=limits.timeout_seconds,
            check=False,
        )
        if result.returncode:
            return _failure(case_id, "parser.worker_failed")
        return EvidenceV1.model_validate_json(result.stdout)
    except subprocess.TimeoutExpired:
        return _failure(case_id, "parser.timeout")
    except (OSError, ValueError):
        return _failure(case_id, "parser.worker_failed")


def parse_eml_file(path: Path, *, case_id: UUID, limits: ParseLimits | None = None) -> EvidenceV1:
    """Read at most message_bytes + 1 from a caller-selected regular local file."""
    limits = limits or ParseLimits()
    try:
        if not path.is_file():
            return _failure(case_id, "parser.file_unavailable")
        with path.open("rb") as stream:
            data = stream.read(limits.message_bytes + 1)
    except OSError:
        return _failure(case_id, "parser.file_unavailable")
    return parse_eml(data, case_id=case_id, limits=limits)
