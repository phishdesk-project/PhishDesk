"""Round-trip across the owner boundary: cyber evidence -> AI verdict -> validation.

Every other test in this repository exercises one side of the project. The
cybersecurity package produces Evidence v1; the analysis package builds the
labelled corpus. Nothing yet carries a message from one side to the other, so a
contract that is wrong in meaning rather than in shape would stay invisible
until the real analyser is built in M2.

These tests close that gap using the real C02 -> C03 pipeline and a deliberately
trivial stand-in analyser. The stand-in is NOT a classifier and makes no
detection claim: it exists to prove that Evidence v1 carries everything an
analyser needs, that a Verdict v1 built only from the contract validates, and
that the safety properties hold at the boundary rather than only inside one
package.

Replace `stub_analyse` with the real analyser when A05 lands; the assertions
below should continue to hold unchanged.
"""

from datetime import date
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from phishdesk.checks import CheckContext, check_eml
from phishdesk.contracts import EvidenceV1, VerdictV1, validate_exchange

# Reason is not re-exported from phishdesk.contracts, but an analyser cannot build a
# Verdict without it. Imported from the versioned module here rather than widening the
# package surface, which is a contract change and belongs to S02.
from phishdesk.contracts.v1 import Reason
from phishdesk_analysis.records import PHISHING_CATEGORIES, Category

ROOT = Path(__file__).resolve().parents[2]
MIME = ROOT / "tests" / "fixtures" / "mime"
CHECKS = ROOT / "tests" / "fixtures" / "checks"
CHECKS_CONTEXT = ROOT / "examples" / "checks-context.json"

CASE = UUID("00000000-0000-4000-8000-00000000d001")
RISK_ORDER = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}

# The corpus taxonomy the AI track labels against, mapped onto contract risk labels.
# This mapping is the actual hand-off point between the two packages: if either side
# adds a category or a risk level, this table must be revisited.
CATEGORY_RISK: dict[Category, str] = {
    Category.CREDENTIAL: "Dangerous",
    Category.PAYMENT: "Dangerous",
    Category.IMPERSONATION: "Suspicious",
    Category.URGENCY: "Suspicious",
    Category.BENIGN: "Safe",
    Category.LEGIT_URGENT: "Safe",
}

MIME_FILES = sorted(MIME.glob("*.eml"))
CHECKS_FILES = sorted(CHECKS.glob("*.eml"))


def plain_context() -> CheckContext:
    """Fixed as_of keeps any age reasoning reproducible."""
    return CheckContext(as_of=date(2026, 1, 1), reference_domains=("fablebank.test",))


def checks_context() -> CheckContext:
    """The committed offline observations the C03 fixtures were authored against."""
    return CheckContext.model_validate_json(CHECKS_CONTEXT.read_bytes())


def evidence_for(path: Path, context: CheckContext, case_id: UUID = CASE) -> EvidenceV1:
    """Run the real parser and deterministic checks over a synthetic fixture."""
    return check_eml(path.read_bytes(), case_id=case_id, context=context)


def stub_analyse(evidence: EvidenceV1) -> VerdictV1:
    """Stand in for the real analyser, using ONLY the contract surface.

    Deliberately crude: it takes the deterministic risk floor as the label and cites
    the findings that produced it. It imports nothing from the parsing or checks
    internals, which is the point - if this function cannot be written against
    Evidence v1 alone, the contract is missing something an analyser needs.
    """
    floor = max((RISK_ORDER[f.severity] for f in evidence.findings), default=0)
    label = next(name for name, rank in RISK_ORDER.items() if rank == floor)

    if evidence.findings:
        reasons = tuple(
            Reason(summary=f.detail, evidence_refs=(f.id,)) for f in evidence.findings[:30]
        )
    else:
        reasons = (
            Reason(
                summary="No deterministic finding was raised for this message.",
                evidence_refs=("message.subject",),
            ),
        )

    # Missing evidence must surface as uncertainty, never be silently dropped.
    uncertainty = tuple(evidence.missing_evidence[:99])
    if evidence.sandbox_state != "succeeded":
        uncertainty = uncertainty + ("No sandbox evidence was available for this message.",)

    return VerdictV1(
        case_id=evidence.case_id,
        label=label,
        confidence=0.5,
        reasons=reasons,
        uncertainty=uncertainty,
    )


CASES = [(p, "plain") for p in MIME_FILES] + [(p, "checks") for p in CHECKS_FILES]
CASE_IDS = [f"{p.parent.name}/{p.name}" for p, _ in CASES]
CONTEXTS = {"plain": plain_context, "checks": checks_context}


def test_fixture_corpora_are_present():
    """Guard against the corpora moving and these tests silently covering nothing."""
    assert MIME_FILES, f"no .eml fixtures under {MIME}"
    assert CHECKS_FILES, f"no .eml fixtures under {CHECKS}"


@pytest.mark.parametrize("path,context_name", CASES, ids=CASE_IDS)
def test_round_trip_validates_for_every_fixture(path, context_name):
    """Parse -> check -> analyse -> validate, end to end, on real fixtures."""
    evidence = evidence_for(path, CONTEXTS[context_name]())
    validate_exchange(evidence, stub_analyse(evidence))


@pytest.mark.parametrize("path,context_name", CASES, ids=CASE_IDS)
def test_round_trip_survives_serialisation(path, context_name):
    """The hand-off is JSON over a queue or an API, not shared Python objects."""
    evidence = evidence_for(path, CONTEXTS[context_name]())
    verdict = stub_analyse(evidence)
    validate_exchange(
        EvidenceV1.model_validate_json(evidence.model_dump_json()),
        VerdictV1.model_validate_json(verdict.model_dump_json()),
    )


def test_checks_fixtures_actually_raise_findings():
    """If this fails, the safety assertions below are no longer exercising anything."""
    raised = [p.name for p in CHECKS_FILES if evidence_for(p, checks_context()).findings]
    assert raised, "no C03 fixture raised a deterministic finding"


def test_analyser_sees_case_identity_from_evidence_alone():
    """Case identity crosses the boundary inside the contract, not out of band."""
    case_id = uuid4()
    evidence = evidence_for(MIME_FILES[0], plain_context(), case_id=case_id)
    assert stub_analyse(evidence).case_id == case_id


# --- Safety properties, asserted at the boundary rather than inside one package ---


def risky_evidence() -> EvidenceV1:
    """The first checks fixture that produces a non-Safe deterministic floor."""
    for path in CHECKS_FILES:
        evidence = evidence_for(path, checks_context())
        if any(RISK_ORDER[f.severity] > 0 for f in evidence.findings):
            return evidence
    raise AssertionError("no fixture produced a non-Safe deterministic finding")


def test_analyser_cannot_lower_the_deterministic_risk_floor():
    """A model must never talk a hard finding down to something safer."""
    evidence = risky_evidence()
    honest = stub_analyse(evidence)
    assert RISK_ORDER[honest.label] > 0
    downgraded = honest.model_copy(update={"label": "Safe"})
    with pytest.raises(ValueError, match="lowered deterministic risk floor"):
        validate_exchange(evidence, downgraded)


def test_analyser_may_raise_risk_above_the_floor():
    """The floor is a minimum, not a ceiling: an analyser can still escalate."""
    evidence = risky_evidence()
    escalated = stub_analyse(evidence).model_copy(update={"label": "Dangerous"})
    validate_exchange(evidence, escalated)


def test_analyser_cannot_cite_evidence_that_does_not_exist():
    """Reasons must point at real evidence, so a verdict stays auditable."""
    evidence = evidence_for(MIME_FILES[0], plain_context())
    invented = stub_analyse(evidence).model_copy(
        update={"reasons": (Reason(summary="Invented.", evidence_refs=("c99.not.real",)),)}
    )
    with pytest.raises(ValueError, match="unknown evidence"):
        validate_exchange(evidence, invented)


def test_missing_evidence_must_surface_as_uncertainty():
    """Gaps in evidence have to reach the analyst, not be quietly absorbed."""
    evidence = evidence_for(MIME_FILES[0], plain_context()).model_copy(
        update={"missing_evidence": ("Domain age was not available.",)}
    )
    silent = stub_analyse(evidence).model_copy(update={"uncertainty": ()})
    with pytest.raises(ValueError, match="Missing evidence requires visible uncertainty"):
        validate_exchange(evidence, silent)


def test_case_identity_mismatch_is_rejected():
    """Evidence and verdict for different cases must never be paired."""
    evidence = evidence_for(MIME_FILES[0], plain_context())
    other = stub_analyse(evidence).model_copy(update={"case_id": uuid4()})
    with pytest.raises(ValueError, match="Case identity mismatch"):
        validate_exchange(evidence, other)


def test_verdict_carries_no_authorisation():
    """A verdict is an opinion. Nothing in it can authorise a mailbox action."""
    assert not set(VerdictV1.model_fields) & {
        "approved",
        "execute",
        "action",
        "quarantine",
        "authorised",
    }


# --- The taxonomy hand-off between the two packages ---


def test_every_corpus_category_maps_to_a_contract_risk_label():
    """A category the AI track can label but the contract cannot express is a gap."""
    assert set(CATEGORY_RISK) == set(Category)
    assert set(CATEGORY_RISK.values()) <= set(RISK_ORDER)


def test_phishing_categories_never_map_to_safe():
    """Corpus-labelled phishing must not be expressible as a Safe verdict."""
    for category in PHISHING_CATEGORIES:
        assert CATEGORY_RISK[category] != "Safe", category


def test_non_phishing_categories_are_not_marked_dangerous():
    """legit_urgent exists so urgency alone is not treated as an attack."""
    for category in set(Category) - PHISHING_CATEGORIES:
        assert CATEGORY_RISK[category] == "Safe", category
