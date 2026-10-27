"""Offline synthetic exchange. No model, network, mailbox or actions."""

import json
from uuid import UUID

from phishdesk.contracts import EvidenceV1, VerdictV1, validate_exchange
from phishdesk.contracts.v1 import Finding, Reason


def fixture_exchange() -> tuple[EvidenceV1, VerdictV1]:
    case_id = UUID("00000000-0000-4000-8000-000000000001")
    evidence = EvidenceV1(
        case_id=case_id,
        source="synthetic",
        subject="FableBank lab account reminder",
        body_text="Invented message for contract development. No link visits or mailbox actions.",
        from_address="lab@fablebank.test",
        findings=(
            Finding(
                id="finding.lab",
                check="synthetic_fixture",
                severity="Suspicious",
                confidence=1.0,
                detail="Deliberately suspicious synthetic lab case",
                evidence_refs=("message.subject",),
            ),
        ),
        missing_evidence=("Authentication and sandbox checks have not run",),
    )
    verdict = VerdictV1(
        case_id=case_id,
        label="Suspicious",
        confidence=0.5,
        reasons=(
            Reason(
                summary="Fixture-only result; no phishing detection has run",
                evidence_refs=("finding.lab",),
            ),
        ),
        uncertainty=("Synthetic mock only; missing authentication and sandbox evidence",),
    )
    validate_exchange(evidence, verdict)
    return evidence, verdict


def main() -> None:
    evidence, verdict = fixture_exchange()
    print(
        json.dumps(
            {
                "mode": "synthetic_mock",
                "evidence": evidence.model_dump(mode="json"),
                "verdict": verdict.model_dump(mode="json"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
