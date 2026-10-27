"""Draft v1 contracts, requiring both owners' review before implementation use."""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Text = Annotated[str, Field(min_length=1, max_length=2000)]
Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Risk = Literal["Safe", "Suspicious", "Dangerous"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvidenceItem(Contract):
    id: Identifier


class Finding(EvidenceItem):
    id: Identifier
    check: Identifier
    severity: Risk
    confidence: Probability
    detail: Text
    evidence_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=30)]


class AuthenticationSignal(EvidenceItem):
    id: Identifier
    mechanism: Literal["spf", "dkim", "dmarc"]
    result: Literal["pass", "fail", "unknown", "not_checked"]
    provenance: Literal["trusted_ingress", "unverified_header", "not_checked"]


class Link(EvidenceItem):
    id: Identifier
    # Untrusted text only: this type does not resolve or visit a URL.
    value: Annotated[str, Field(min_length=1, max_length=4096)]


class Attachment(EvidenceItem):
    id: Identifier
    filename: Annotated[str, Field(min_length=1, max_length=255)]
    size_bytes: Annotated[int, Field(ge=0)]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None


class SandboxArtifact(EvidenceItem):
    id: Identifier
    kind: Literal["screenshot", "redirect", "form", "resource"]
    summary: Text


class EvidenceV1(Contract):
    schema_version: Literal["evidence.v1"] = "evidence.v1"
    case_id: UUID
    source: Literal["synthetic", "imap", "gmail", "graph"]
    subject: Annotated[str, Field(max_length=1000)]
    body_text: Annotated[str, Field(max_length=100000)]
    from_address: Annotated[str, Field(max_length=1000)]
    reply_to: Annotated[str, Field(max_length=1000)] | None = None
    authentication: Annotated[tuple[AuthenticationSignal, ...], Field(max_length=3)] = ()
    links: Annotated[tuple[Link, ...], Field(max_length=200)] = ()
    attachments: Annotated[tuple[Attachment, ...], Field(max_length=100)] = ()
    sandbox_artifacts: Annotated[tuple[SandboxArtifact, ...], Field(max_length=200)] = ()
    sandbox_state: Literal["not_run", "succeeded", "failed", "timeout"] = "not_run"
    findings: Annotated[tuple[Finding, ...], Field(max_length=200)] = ()
    missing_evidence: Annotated[tuple[Text, ...], Field(max_length=100)] = ()

    @model_validator(mode="after")
    def unique_evidence(self) -> "EvidenceV1":
        ids = [
            x.id
            for x in (
                *self.authentication,
                *self.links,
                *self.attachments,
                *self.sandbox_artifacts,
                *self.findings,
            )
        ]
        reserved = {"message.subject", "message.body_text", "sender.from_address"}
        if len(ids) != len(set(ids)) or reserved.intersection(ids):
            raise ValueError("Evidence IDs must be unique and not shadow reserved references")
        if self.sandbox_artifacts and self.sandbox_state != "succeeded":
            raise ValueError("Sandbox artefacts require a successful job")
        for finding in self.findings:
            if not set(finding.evidence_refs) <= (set(ids) | reserved) - {finding.id}:
                raise ValueError("Finding refers to unknown or self evidence")
        return self


class Reason(Contract):
    summary: Text
    evidence_refs: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=30)]


class ModelSignal(Contract):
    model_id: Identifier
    model_version: Text
    score: Probability


class VerdictV1(Contract):
    schema_version: Literal["verdict.v1"] = "verdict.v1"
    case_id: UUID
    label: Risk
    confidence: Probability
    reasons: Annotated[tuple[Reason, ...], Field(min_length=1, max_length=30)]
    uncertainty: Annotated[tuple[Text, ...], Field(max_length=100)]
    model_signals: Annotated[tuple[ModelSignal, ...], Field(max_length=20)] = ()
    injection_flags: Annotated[tuple[Text, ...], Field(max_length=100)] = ()


class ActionTarget(Contract):
    provider: Literal["gmail", "graph"]
    mailbox_id: Identifier
    message_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def unique_targets(self) -> "ActionTarget":
        if len(self.message_ids) != len(set(self.message_ids)):
            raise ValueError("Duplicate target message IDs")
        return self


class ActionRequestV1(Contract):
    schema_version: Literal["action-request.v1"] = "action-request.v1"
    request_id: UUID
    case_id: UUID
    action: Literal["quarantine", "restore"]
    targets: Annotated[tuple[ActionTarget, ...], Field(min_length=1, max_length=10)]
    reason: Text
    risk: Literal["Suspicious", "Dangerous"]
    approval_required: Literal[True] = True
    rollback_description: Text
    # No approved/execute field: authorisation belongs to a future backend state machine.


def validate_exchange(evidence: EvidenceV1, verdict: VerdictV1) -> None:
    """Check identity, reference integrity and a minimum deterministic risk floor."""
    if evidence.case_id != verdict.case_id:
        raise ValueError("Case identity mismatch")
    known = {"message.subject", "message.body_text", "sender.from_address"}
    known.update(
        x.id
        for x in (
            *evidence.authentication,
            *evidence.links,
            *evidence.attachments,
            *evidence.sandbox_artifacts,
            *evidence.findings,
        )
    )
    if any(not set(reason.evidence_refs) <= known for reason in verdict.reasons):
        raise ValueError("Verdict refers to unknown evidence")
    risk_order = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}
    floor = max((risk_order[f.severity] for f in evidence.findings), default=0)
    if risk_order[verdict.label] < floor:
        raise ValueError("Verdict lowered deterministic risk floor")
    if evidence.missing_evidence and not verdict.uncertainty:
        raise ValueError("Missing evidence requires visible uncertainty")
