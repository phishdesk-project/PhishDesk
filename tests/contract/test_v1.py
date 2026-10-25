import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from phishdesk.contracts import ActionRequestV1, EvidenceV1, VerdictV1, validate_exchange
from phishdesk.demo import fixture_exchange


def test_exchange_round_trip():
    evidence, verdict = fixture_exchange()
    validate_exchange(
        EvidenceV1.model_validate_json(evidence.model_dump_json()),
        VerdictV1.model_validate_json(verdict.model_dump_json()),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("confidence", -0.1),
        ("confidence", 1.1),
        ("confidence", float("nan")),
        ("confidence", float("inf")),
        ("approved", True),
        ("schema_version", "verdict.v2"),
    ],
)
def test_reject_untrusted_model_fields(field, value):
    payload = fixture_exchange()[1].model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        VerdictV1.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("change", ["identity", "reference", "risk_floor", "uncertainty"])
def test_exchange_rejects_unsafe_disagreement(change):
    evidence, verdict = fixture_exchange()
    payload = verdict.model_dump(mode="json")
    if change == "identity":
        payload["case_id"] = str(UUID(int=2))
    elif change == "reference":
        payload["reasons"][0]["evidence_refs"] = ["invented.evidence"]
    elif change == "risk_floor":
        payload["label"] = "Safe"
    else:
        payload["uncertainty"] = []
    with pytest.raises(ValueError):
        validate_exchange(evidence, VerdictV1.model_validate_json(json.dumps(payload)))


def action_payload():
    return {
        "request_id": str(UUID(int=3)),
        "case_id": str(UUID(int=1)),
        "action": "quarantine",
        "targets": [{"provider": "gmail", "mailbox_id": "lab", "message_ids": ["fixture-1"]}],
        "reason": "Synthetic proposal",
        "risk": "Suspicious",
        "rollback_description": "Restore fixture-1",
    }


@pytest.mark.parametrize("change", ["no_approval", "execute", "wildcard", "empty", "duplicate"])
def test_action_is_scoped_proposal_never_authorisation(change):
    payload = action_payload()
    if change == "no_approval":
        payload["approval_required"] = False
    elif change == "execute":
        payload["execute"] = True
    elif change == "wildcard":
        payload["targets"][0]["mailbox_id"] = "*"
    elif change == "empty":
        payload["targets"] = []
    else:
        payload["targets"][0]["message_ids"] = ["fixture-1", "fixture-1"]
    with pytest.raises(ValidationError):
        ActionRequestV1.model_validate_json(json.dumps(payload))


def test_valid_proposal_still_requires_approval():
    assert ActionRequestV1.model_validate_json(json.dumps(action_payload())).approval_required


def test_duplicate_evidence_rejected():
    payload = fixture_exchange()[0].model_dump(mode="json")
    payload["links"] = [{"id": "finding.lab", "value": "https://example.test"}]
    with pytest.raises(ValidationError):
        EvidenceV1.model_validate_json(json.dumps(payload))


def test_committed_action_fixture_is_a_proposal():
    path = Path(__file__).resolve().parents[2] / "examples/fixtures/action-request.json"
    proposal = ActionRequestV1.model_validate_json(path.read_text())
    assert proposal.approval_required is True
    assert proposal.case_id == fixture_exchange()[0].case_id
