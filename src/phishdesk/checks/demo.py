"""Scripted C02 -> C03 -> mock Verdict exchange; metadata/static codes only."""

import json
from pathlib import Path
from uuid import UUID

from phishdesk.checks import CheckContext, check_eml
from phishdesk.contracts import validate_exchange
from phishdesk.contracts.v1 import Reason, VerdictV1


def main() -> None:
    context = CheckContext.model_validate_json(Path("examples/checks-context.json").read_bytes())
    paths = sorted(Path("tests/fixtures/checks").glob("*.eml"))
    if len(paths) != 5:
        raise SystemExit("Expected 5 synthetic C03 fixtures")
    summaries = []
    for index, path in enumerate(paths, 1):
        evidence = check_eml(path.read_bytes(), case_id=UUID(int=index), context=context)
        if {"parser.timeout", "parser.worker_failed", "parser.malformed"}.intersection(
            evidence.missing_evidence
        ):
            raise SystemExit("Fixture parser failed")
        # Scripted integration fixture, never an AI or production triage decision.
        verdict = VerdictV1(
            case_id=evidence.case_id,
            label="Suspicious",
            confidence=0.5,
            reasons=(
                Reason(
                    summary="Scripted synthetic C03 exchange; no safety verdict is established",
                    evidence_refs=(
                        evidence.findings[0].id if evidence.findings else "sender.from_address",
                    ),
                ),
            ),
            uncertainty=evidence.missing_evidence,
        )
        validate_exchange(evidence, verdict)
        summaries.append(
            {
                "sample": index,
                "links": len(evidence.links),
                "checks": sorted({f.check for f in evidence.findings}),
                "findings": len(evidence.findings),
                "authentication": [a.model_dump(exclude={"id"}) for a in evidence.authentication],
                "missing_evidence": evidence.missing_evidence,
                "exchange_valid": True,
            }
        )
    print(
        json.dumps(
            {"mode": "synthetic_checks", "validated": len(paths), "samples": summaries}, indent=2
        )
    )


if __name__ == "__main__":
    main()
