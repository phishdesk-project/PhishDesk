"""Bounded offline C03 checks. Observations are indicators, never a safe verdict."""

import ipaddress
import re
from datetime import date
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, model_validator

from phishdesk.contracts import EvidenceV1
from phishdesk.contracts.v1 import AuthenticationSignal, Contract, Finding, Identifier, Risk
from phishdesk.parsing import ParseLimits, parse_eml

Domain = Annotated[str, Field(min_length=1, max_length=253)]
MECHANISMS: tuple[Literal["spf", "dkim", "dmarc"], ...] = ("spf", "dkim", "dmarc")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*\Z")


def _domain(value: str) -> str | None:
    """Conservative DNS syntax only; no DNS, PSL, browser or ownership claim."""
    if not value or len(value) > 253 or any(c.isspace() or ord(c) < 32 for c in value):
        return None
    try:
        value = value.removesuffix(".").encode("idna").decode("ascii").lower()
        labels = value.split(".")
        if len(value) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(x) for x in labels):
            return None
        if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", labels[-1]):
            return None
        # Validate A-labels rather than accepting any xn-- string as IDNA.
        for label in labels:
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
        return value
    except UnicodeError:
        return None


def _mailbox(value: str) -> str | None:
    """Accept one simple mailbox; ambiguous/unsupported grammar stays unknown."""
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    value = value.strip()
    if "<" in value or ">" in value:
        match = re.fullmatch(r"[^<>@,;:()\[\]\\]*<([^<>]+)>", value)
        if not match:
            return None
        value = match[1]
    if value.count("@") != 1:
        return None
    local, domain = value.split("@")
    if len(local) > 64 or not LOCAL.fullmatch(local):
        return None
    return _domain(domain)


class IngressAuthentication(Contract):
    """Caller assertion from a trusted adapter, never constructed from mail text."""

    mechanism: Literal["spf", "dkim", "dmarc"]
    result: Literal["pass", "fail", "unknown", "not_checked"]


class DomainAgeObservation(Contract):
    """Offline host-specific observation. No provider is invoked by C03."""

    domain: Domain
    source: Identifier
    status: Literal["ok", "unknown", "failed", "timeout"]
    observed_on: date
    created_on: date | None = None

    @model_validator(mode="after")
    def valid_domain(self) -> "DomainAgeObservation":
        if _domain(self.domain) is None:
            raise ValueError("Domain-age observations require a DNS hostname")
        return self


class CheckContext(Contract):
    """Explicit date makes age calculations reproducible; all collections bounded."""

    as_of: date
    reference_domains: Annotated[tuple[Domain, ...], Field(max_length=50)] = ()
    domain_ages: Annotated[tuple[DomainAgeObservation, ...], Field(max_length=200)] = ()
    trusted_authentication: Annotated[tuple[IngressAuthentication, ...], Field(max_length=3)] = ()

    @model_validator(mode="after")
    def unique_inputs(self) -> "CheckContext":
        refs = [_domain(x) for x in self.reference_domains]
        ages = [_domain(x.domain) for x in self.domain_ages]
        auth = [x.mechanism for x in self.trusted_authentication]
        if None in refs or len(refs) != len(set(refs)):
            raise ValueError("Reference domains must be valid and unique")
        if len(ages) != len(set(ages)) or len(auth) != len(set(auth)):
            raise ValueError("Duplicate domain-age or authentication observations")
        return self


class _Budget:
    def __init__(self, evidence: EvidenceV1) -> None:
        self.findings = list(evidence.findings)
        self.missing = list(evidence.missing_evidence)
        self.ids = {"message.subject", "message.body_text", "sender.from_address"}
        self.ids.update(
            x.id
            for x in (
                *evidence.authentication,
                *evidence.links,
                *evidence.attachments,
                *evidence.sandbox_artifacts,
                *evidence.findings,
            )
        )

    def note(self, code: str) -> None:
        if code not in self.missing:
            if len(self.missing) == 100:
                raise ValueError("No Evidence v1 capacity to record C03 uncertainty")
            self.missing.append(code)

    def identifier(self, prefix: str) -> str:
        index = 1
        while f"{prefix}.{index}" in self.ids:
            index += 1
        result = f"{prefix}.{index}"
        self.ids.add(result)
        return result

    def finding(
        self,
        check: str,
        detail: str,
        refs: tuple[str, ...],
        confidence: float,
        severity: Risk = "Suspicious",
    ) -> None:
        if len(self.findings) == 200:
            self.note("c03.findings_limit")
            return
        self.findings.append(
            Finding(
                id=self.identifier("c03.finding"),
                check=check,
                severity=severity,
                confidence=confidence,
                detail=detail,
                evidence_refs=refs,
            )
        )


def _one_edit(a: str, b: str) -> bool:
    """At most one insertion, deletion or substitution, linear in hostname length."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    for index, char in enumerate(a):
        if char != b[index]:
            return (
                a[index + 1 :] == b[index + 1 :]
                if len(a) == len(b)
                else a[index:] == b[index + 1 :]
            )
    return True


def _lookalike(host: str, references: tuple[str, ...]) -> str | None:
    # Reference and its proper subdomains are excluded, without guessing eTLD+1.
    if any(host == ref or host.endswith("." + ref) for ref in references):
        return None
    for ref in references:
        candidate = ".".join(host.split(".")[-len(ref.split(".")) :])
        if _one_edit(candidate, ref):
            return f"hostname is one edit from configured reference={ref} (heuristic)"
        if host.startswith(ref + ".") or ("." + ref + ".") in host:
            return f"configured reference={ref} appears beneath another hostname (heuristic)"
    return None


def _age(
    host: str,
    context: CheckContext,
    observations: dict[str, DomainAgeObservation],
    budget: _Budget,
    refs: tuple[str, ...],
) -> None:
    observation = observations.get(host)
    if observation is None:
        budget.note("c03.domain_age.not_checked")
        return
    if observation.status != "ok":
        budget.note("c03.domain_age." + observation.status)
        return
    created, observed = observation.created_on, observation.observed_on
    if created is None or created > observed or observed > context.as_of:
        budget.note("c03.domain_age.invalid")
        return
    if (context.as_of - observed).days > 30:
        budget.note("c03.domain_age.stale")
        return
    days = (context.as_of - created).days
    budget.finding(
        "c03.domain_age",
        f"domain age {days} days; threshold <30; offline caller source="
        f"{observation.source}; created={created}; observed={observed}; "
        f"as_of={context.as_of}; domain age alone never proves safety or phishing",
        refs,
        1.0,
        "Suspicious" if days < 30 else "Safe",
    )


def run_checks(evidence: EvidenceV1, *, context: CheckContext) -> EvidenceV1:
    """Enrich validated Evidence v1; preserve parser fields and existing references.

    Never trust authentication provenance asserted inside serialized Evidence.
    Trusted ingress results must arrive separately in context from reviewed code.
    """
    evidence = EvidenceV1.model_validate_json(evidence.model_dump_json())
    context = CheckContext.model_validate_json(context.model_dump_json())
    budget = _Budget(evidence)
    observations = {host: x for x in context.domain_ages if (host := _domain(x.domain)) is not None}
    references = tuple(x for r in context.reference_domains if (x := _domain(r)) is not None)
    if not references:
        budget.note("c03.lookalike.not_configured")
    original = {a.mechanism: a for a in evidence.authentication}
    if len(original) != len(evidence.authentication):
        raise ValueError("Ambiguous duplicate authentication mechanisms")
    trusted = {a.mechanism: a for a in context.trusted_authentication}
    authentication = []
    for mechanism in MECHANISMS:
        prior, ingress = original.get(mechanism), trusted.get(mechanism)
        unverified = prior is not None and not (
            prior.provenance == "not_checked" and prior.result == "not_checked"
        )
        signal = AuthenticationSignal(
            id=prior.id if prior else budget.identifier("c03.auth." + mechanism),
            mechanism=mechanism,
            result=ingress.result if ingress else ("unknown" if unverified else "not_checked"),
            provenance="trusted_ingress"
            if ingress
            else ("unverified_header" if unverified else "not_checked"),
        )
        authentication.append(signal)
        if signal.result in {"unknown", "not_checked"}:
            budget.note(f"c03.authentication.{mechanism}.{signal.result}")
        if not ingress and unverified:
            budget.note("c03.authentication.unverified_header")
        if ingress and ingress.result == "fail":
            budget.finding(
                "c03.authentication",
                f"{mechanism} failed at trusted ingress; "
                "this is an authentication indicator, not proof of phishing",
                (signal.id,),
                1.0,
            )
    sender = _mailbox(evidence.from_address)
    reply = _mailbox(evidence.reply_to) if evidence.reply_to is not None else None
    if sender is None:
        budget.note("c03.sender.unknown")
    if evidence.reply_to is None:
        budget.note("c03.reply_to.absent")
    elif reply is None:
        budget.note("c03.reply_to.unknown")
    if sender and reply and sender != reply:
        budget.finding(
            "c03.reply_to_mismatch",
            "From and Reply-To have different normalized "
            "DNS domains; legitimate services may also do this. Reply-To is the "
            "preserved message.reply_to field (v1 has no reserved Reply-To ref)",
            ("sender.from_address",),
            1.0,
        )
    if sender:
        indicator = _lookalike(sender, references)
        _age(sender, context, observations, budget, ("sender.from_address",))
        if any(x.startswith("xn--") for x in sender.split(".")):
            indicator = (indicator + "; " if indicator else "") + (
                "internationalized sender hostname; visual similarity not established"
            )
        if indicator:
            budget.finding("c03.sender_domain", indicator, ("sender.from_address",), 0.6)
    for link in evidence.links:
        indicators = []
        value = link.value
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
            budget.note("c03.url.unknown")
            budget.finding(
                "c03.url",
                "URL contains whitespace, controls or backslash; browser interpretation is unknown",
                (link.id,),
                1.0,
            )
            continue
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
            if parsed.scheme.lower() not in {"http", "https"} or not host or port == 0:
                raise ValueError
            if parsed.netloc.endswith(":") or "%" in host:
                raise ValueError
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            if not is_ip and re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", host.split(".")[-1], re.I):
                raise ValueError
            domain = None if is_ip else _domain(host)
            if not is_ip and domain is None:
                raise ValueError
        except ValueError:
            budget.note("c03.url.unknown")
            budget.finding(
                "c03.url", "Malformed or unsupported HTTP(S) URL; host/age unknown", (link.id,), 1.0
            )
            continue
        if parsed.username is not None or parsed.password is not None:
            indicators.append("userinfo in authority can obscure the actual host")
        if parsed.scheme.lower() == "http":
            indicators.append("unencrypted HTTP scheme")
        if is_ip:
            indicators.append("IP-literal host; no domain-age inference")
            budget.note("c03.domain_age.not_applicable")
        if port is not None and port != (443 if parsed.scheme.lower() == "https" else 80):
            indicators.append("non-default port")
        if not host.isascii() or (domain and any(x.startswith("xn--") for x in domain.split("."))):
            indicators.append("internationalized hostname; visual similarity not established")
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            indicators.append("invalid percent escape")
            budget.note("c03.url.unknown")
        if domain:
            lookalike = _lookalike(domain, references)
            if lookalike:
                indicators.append(lookalike)
            _age(domain, context, observations, budget, (link.id,))
        if indicators:
            budget.finding(
                "c03.url",
                "; ".join(indicators) + "; indicators do not prove phishing",
                (link.id,),
                0.6,
            )
    result = evidence.model_dump(mode="python")
    result.update(
        authentication=tuple(authentication),
        findings=tuple(budget.findings),
        missing_evidence=tuple(budget.missing),
    )
    return EvidenceV1.model_validate(result)


def check_eml(
    data: bytes, *, case_id: UUID, context: CheckContext, limits: ParseLimits | None = None
) -> EvidenceV1:
    """C02 -> C03 integration. Header presence never verifies SPF/DKIM/DMARC."""
    limits = limits or ParseLimits()
    evidence = parse_eml(data, case_id=case_id, limits=limits)
    # Only scan a bounded root header block. Never parse claimed auth results.
    prefix = data[: limits.header_bytes + 4]
    separator = re.search(rb"\A\r?\n|\r?\n\r?\n", prefix)
    if len(data) <= limits.message_bytes and separator and separator.start() <= limits.header_bytes:
        block = prefix[: separator.start()]
        if re.search(rb"(?im)^Authentication-Results:", block):
            result = evidence.model_dump(mode="python")
            result["authentication"] = tuple(
                AuthenticationSignal(
                    id=f"c03.header.{mechanism}",
                    mechanism=mechanism,
                    result="unknown",
                    provenance="unverified_header",
                )
                for mechanism in MECHANISMS
            )
            evidence = EvidenceV1.model_validate(result)
    return run_checks(evidence, context=context)
