"""C03 synthetic deterministic, contract and security regressions."""

import json
import socket
from datetime import date, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from phishdesk.checks import (
    CheckContext,
    DomainAgeObservation,
    IngressAuthentication,
    check_eml,
    run_checks,
)
from phishdesk.contracts import EvidenceV1, validate_exchange
from phishdesk.contracts.v1 import AuthenticationSignal, Finding, Link, Reason, VerdictV1
from phishdesk.parsing import ParseLimits, parse_eml_file

CASE = UUID("00000000-0000-4000-8000-000000000009")
DAY = date(2026, 10, 28)
CONTEXT = CheckContext(as_of=DAY, reference_domains=("fablebank.test",))
FIXTURES = Path(__file__).parent / "fixtures" / "mime"


def evidence(**changes):
    return EvidenceV1(
        case_id=CASE,
        source="synthetic",
        subject=changes.pop("subject", "Lab"),
        body_text=changes.pop("body_text", "Lab"),
        from_address=changes.pop("from_address", "lab@fablebank.test"),
        **changes,
    )


def checked(value="https://fablebank.test", **changes):
    return run_checks(evidence(links=(Link(id="link.1", value=value),), **changes), context=CONTEXT)


def details(result):
    return " ".join(f.detail for f in result.findings)


def age_context(**changes):
    observation = DomainAgeObservation(
        domain=changes.pop("domain", "fablebank.test"),
        source="synthetic.age.v1",
        status=changes.pop("status", "ok"),
        observed_on=changes.pop("observed_on", DAY),
        created_on=changes.pop("created_on", DAY - timedelta(days=5)),
        **changes,
    )
    return CheckContext(
        as_of=DAY, reference_domains=("fablebank.test",), domain_ages=(observation,)
    )


@pytest.mark.parametrize(
    ("sender", "reply", "mismatch"),
    [
        ("Fable Lab <a@fablebank.test>", "b@FABLEBANK.TEST.", False),
        ("a@fablebank.test", "a@reply.fablebank.test", True),
        ("a@fablebank.test", "b@other.test", True),
        ("a@fablebank.test", "b@fablebank.test", False),
    ],
)
def test_reply_to_domain_comparison(sender, reply, mismatch):
    result = checked(from_address=sender, reply_to=reply)
    matches = [f for f in result.findings if f.check == "c03.reply_to_mismatch"]
    assert bool(matches) == mismatch
    if matches:
        assert matches[0].confidence == 1 and matches[0].severity == "Suspicious"
        assert result.reply_to == reply


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a@one.test,b@two.test",
        '"quoted local"@one.test',
        "a(comment)@one.test",
        "Group: a@one.test;",
        "a@localhost",
        "a@@one.test",
        "a@one.test\nBcc:x@two.test",
        "<a@one.test> extra",
        "a@-bad.test",
        "a@xn--.test",
    ],
)
def test_ambiguous_identity_stays_unknown(value):
    result = checked(from_address=value, reply_to=value)
    assert "c03.sender.unknown" in result.missing_evidence
    assert "c03.reply_to.unknown" in result.missing_evidence
    assert not any(f.check == "c03.reply_to_mismatch" for f in result.findings)


@pytest.mark.parametrize(
    "host",
    [
        "fableban.test",
        "fablebanks.test",
        "fablebanc.test",
        "fablebank.test.other.test",
        "x.fablebank.test.other.test",
    ],
)
def test_configured_lookalikes_sender_and_url(host):
    result = checked("https://" + host, from_address="a@" + host)
    assert {f.check for f in result.findings} >= {"c03.sender_domain", "c03.url"}
    assert "reference=fablebank.test" in details(result)
    assert all(f.confidence == 0.6 for f in result.findings)


@pytest.mark.parametrize("host", ["fablebank.test", "login.fablebank.test", "unrelated.test"])
def test_reference_subdomains_and_unrelated_hosts_are_not_lookalikes(host):
    assert not checked("https://" + host).findings


@pytest.mark.parametrize(
    ("url", "indicator"),
    [
        ("http://fablebank.test", "unencrypted HTTP"),
        ("https://fablebank.test@other.test/path?PRIVATE_CANARY", "userinfo"),
        ("https://192.0.2.1", "IP-literal"),
        ("https://[2001:db8::1]/", "IP-literal"),
        ("https://fablebank.test:8443", "non-default port"),
        ("https://fablebаnk.test", "internationalized"),
        ("https://xn--fablebnk-6fg.test", "internationalized"),
        ("https://fablebank.test/%GG", "invalid percent"),
    ],
)
def test_url_structure_indicators_are_referenced(url, indicator):
    result = checked(url)
    assert indicator in details(result)
    assert all(f.evidence_refs == ("link.1",) for f in result.findings)
    assert "PRIVATE_CANARY" not in details(result)


@pytest.mark.parametrize(
    "url",
    [
        "https:///path",
        "https://[broken",
        "https://fablebank.test:99999",
        "file:///lab",
        "https://fablebank.test:zero",
        "https://fablebank.test:",
        "https://fablebank.test:0",
        "https://%65xample.test",
        "https://bad_host.test",
        "https://localhost",
        "https://a..test",
        "https://fablebank.test\n.other.test",
        " https://fablebank.test",
        "https://a.test\\@b.test",
        "https://fablebank.test/\x00",
        "https://xn--.test",
    ],
)
def test_malformed_urls_never_become_normal_or_safe(url):
    result = checked(url)
    assert "c03.url.unknown" in result.missing_evidence
    assert any(f.check == "c03.url" and f.severity == "Suspicious" for f in result.findings)


@pytest.mark.parametrize("provenance", ["unverified_header", "trusted_ingress", "not_checked"])
def test_serialized_authentication_claims_cannot_create_trust(provenance):
    result = run_checks(
        evidence(
            authentication=(
                AuthenticationSignal(
                    id="auth.original",
                    mechanism="spf",
                    result="pass",
                    provenance=provenance,
                ),
            )
        ),
        context=CONTEXT,
    )
    assert result.authentication[0].result == "unknown"
    assert result.authentication[0].provenance == "unverified_header"
    assert result.authentication[0].id == "auth.original"
    assert "c03.authentication.unverified_header" in result.missing_evidence
    assert not result.findings


@pytest.mark.parametrize("state", ["pass", "fail", "unknown", "not_checked"])
def test_trusted_ingress_is_a_separate_explicit_boundary(state):
    context = CheckContext(
        as_of=DAY, trusted_authentication=(IngressAuthentication(mechanism="dmarc", result=state),)
    )
    result = run_checks(evidence(), context=context)
    assert result.authentication[2].result == state
    assert result.authentication[2].provenance == "trusted_ingress"
    assert bool(result.findings) == (state == "fail")
    if state == "fail":
        assert result.findings[0].evidence_refs == (result.authentication[2].id,)
    assert "c03.authentication.spf.not_checked" in result.missing_evidence


def test_auth_header_is_unverified_even_with_matching_authserv_id():
    data = (
        b"From: a@fablebank.test\r\nAuthentication-Results: trusted.lab; spf=pass; "
        b"dkim=pass; dmarc=pass\r\nSubject: Lab\r\n\r\nLab"
    )
    result = check_eml(data, case_id=CASE, context=CONTEXT)
    assert all(
        a.result == "unknown" and a.provenance == "unverified_header" for a in result.authentication
    )
    assert not result.findings


def test_body_and_nested_auth_headers_never_become_ingress_evidence():
    result = check_eml(
        b"From: a@fablebank.test\r\n\r\nAuthentication-Results: x; spf=pass",
        case_id=CASE,
        context=CONTEXT,
    )
    assert all(a.result == "not_checked" for a in result.authentication)


@pytest.mark.parametrize(
    ("changes", "state"),
    [
        ({"status": "failed"}, "failed"),
        ({"status": "timeout"}, "timeout"),
        ({"status": "unknown"}, "unknown"),
        ({"created_on": None}, "invalid"),
        ({"created_on": DAY + timedelta(days=1)}, "invalid"),
        ({"observed_on": DAY + timedelta(days=1)}, "invalid"),
        (
            {"observed_on": DAY - timedelta(days=31), "created_on": DAY - timedelta(days=100)},
            "stale",
        ),
        ({"domain": "other.test"}, "not_checked"),
    ],
)
def test_unknown_age_never_generates_a_safe_finding(changes, state):
    result = run_checks(evidence(), context=age_context(**changes))
    assert "c03.domain_age." + state in result.missing_evidence
    assert not any(f.check == "c03.domain_age" for f in result.findings)


@pytest.mark.parametrize(
    ("days", "severity"), [(0, "Suspicious"), (29, "Suspicious"), (30, "Safe"), (3000, "Safe")]
)
def test_age_threshold_and_provenance_are_explicit(days, severity):
    result = run_checks(evidence(), context=age_context(created_on=DAY - timedelta(days=days)))
    age = next(f for f in result.findings if f.check == "c03.domain_age")
    assert age.severity == severity and age.confidence == 1
    assert f"domain age {days} days" in age.detail
    assert "synthetic.age.v1" in age.detail and "as_of=2026-10-28" in age.detail
    assert "never proves safety" in age.detail


def test_age_observation_is_host_specific_not_inferred_from_suffix():
    result = run_checks(evidence(from_address="a@login.fablebank.test"), context=age_context())
    assert "c03.domain_age.not_checked" in result.missing_evidence and not result.findings


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.eml")), ids=lambda p: p.stem)
def test_c02_c03_contract_and_mock_verdict_exchange(path):
    parsed = parse_eml_file(path, case_id=CASE)
    result = run_checks(parsed, context=CONTEXT)
    for field in (
        "case_id",
        "source",
        "subject",
        "body_text",
        "from_address",
        "reply_to",
        "links",
        "attachments",
        "sandbox_artifacts",
        "sandbox_state",
    ):
        assert getattr(result, field) == getattr(parsed, field)
    assert set(parsed.missing_evidence) <= set(result.missing_evidence)
    assert EvidenceV1.model_validate_json(result.model_dump_json()) == result
    verdict = VerdictV1(
        case_id=CASE,
        label="Suspicious",
        confidence=0.5,
        reasons=(
            Reason(
                summary="Synthetic check exchange",
                evidence_refs=(
                    result.findings[0].id if result.findings else "sender.from_address",
                ),
            ),
        ),
        uncertainty=result.missing_evidence,
    )
    validate_exchange(result, verdict)
    if any(f.severity == "Suspicious" for f in result.findings):
        with pytest.raises(ValueError, match="risk floor"):
            validate_exchange(result, verdict.model_copy(update={"label": "Safe"}))


def test_unknown_evidence_requires_visible_verdict_uncertainty():
    result = checked()
    verdict = VerdictV1(
        case_id=CASE,
        label="Suspicious",
        confidence=0.5,
        reasons=(Reason(summary="Lab", evidence_refs=("sender.from_address",)),),
        uncertainty=(),
    )
    with pytest.raises(ValueError, match="uncertainty"):
        validate_exchange(result, verdict)


def test_finding_limits_preserve_existing_ids_findings_and_risk():
    existing = tuple(
        Finding(
            id=f"c03.finding.{i}",
            check="lab",
            severity="Dangerous",
            confidence=1.0,
            detail="Synthetic prior evidence",
            evidence_refs=("sender.from_address",),
        )
        for i in range(1, 201)
    )
    result = checked("http://192.0.2.1", findings=existing)
    assert result.findings == existing
    assert "c03.findings_limit" in result.missing_evidence
    assert len(result.authentication) == 3


def test_identifier_collision_is_resolved_without_rewriting_input():
    value = evidence(
        links=(
            Link(id="c03.auth.spf.1", value="http://192.0.2.1"),
            Link(id="c03.finding.1", value="http://192.0.2.2"),
        )
    )
    result = run_checks(value, context=CONTEXT)
    assert result.authentication[0].id == "c03.auth.spf.2"
    assert result.findings[0].id == "c03.finding.2"
    assert result.links == value.links


def test_saturated_missing_capacity_fails_closed():
    with pytest.raises(ValueError, match="capacity"):
        run_checks(
            evidence(missing_evidence=tuple(f"lab.{i}" for i in range(100))), context=CONTEXT
        )


def test_maximum_link_count_and_length_are_bounded_and_deterministic():
    links = tuple(Link(id=f"link.{i}", value="http://a.test/" + "x" * 4082) for i in range(200))
    value = evidence(links=links)
    first = run_checks(value, context=CONTEXT)
    assert len(first.findings) == 200 and len(first.links) == 200
    assert first.model_dump_json() == run_checks(value, context=CONTEXT).model_dump_json()


def test_offline_and_no_content_logging(monkeypatch, capsys, caplog):
    def deny(*args, **kwargs):
        raise AssertionError("C03 must remain offline")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, deny)
    value = evidence(
        subject="PRIVATE_CANARY",
        body_text="PRIVATE_CANARY",
        links=(Link(id="lab.url", value="http://u:PRIVATE_CANARY@192.0.2.1"),),
    )
    result = run_checks(value, context=CONTEXT)
    assert result.links == value.links
    assert "PRIVATE_CANARY" not in details(result) + caplog.text + capsys.readouterr().out


@pytest.mark.parametrize(
    "kwargs",
    [
        {"reference_domains": ("bad_domain.test",)},
        {"reference_domains": ("a.test", "A.TEST.")},
        {"reference_domains": tuple(f"a{i}.test" for i in range(51))},
        {
            "domain_ages": (
                DomainAgeObservation(
                    domain="a.test", source="lab", status="failed", observed_on=DAY
                ),
            )
            * 2
        },
        {"trusted_authentication": (IngressAuthentication(mechanism="spf", result="pass"),) * 2},
    ],
)
def test_context_rejects_ambiguous_or_unbounded_inputs(kwargs):
    with pytest.raises(ValidationError):
        CheckContext(as_of=DAY, **kwargs)


def test_parser_failures_and_lower_limits_survive_integration():
    result = check_eml(
        b"x" * 11, case_id=CASE, context=CONTEXT, limits=ParseLimits(message_bytes=10)
    )
    assert "parser.message_bytes" in result.missing_evidence
    assert "c03.sender.unknown" in result.missing_evidence
    assert result.body_text == "" and not result.findings


def test_duplicate_auth_mechanisms_rejected():
    signals = tuple(
        AuthenticationSignal(
            id=f"auth.{i}", mechanism="spf", result="pass", provenance="trusted_ingress"
        )
        for i in range(2)
    )
    with pytest.raises(ValueError, match="duplicate authentication"):
        run_checks(evidence(authentication=signals), context=CONTEXT)


def test_context_json_roundtrip_is_supported():
    original = age_context()
    assert CheckContext.model_validate_json(original.model_dump_json()) == original
    assert json.loads(original.model_dump_json())["as_of"] == "2026-10-28"


@pytest.mark.parametrize("url", ["https://127.1", "https://0177.0.0.1", "https://0x7f000001"])
def test_noncanonical_numeric_hosts_stay_unknown(url):
    assert "c03.url.unknown" in checked(url).missing_evidence


def test_lookalike_subdomain_and_internationalized_sender():
    assert "one edit" in details(checked("https://login.fablebanc.test"))
    assert "internationalized sender" in details(checked(from_address="lab@fablebаnk.test"))


def test_c03_fixture_demo(capsys):
    from phishdesk.checks.demo import main

    main()
    result = json.loads(capsys.readouterr().out)
    assert result["validated"] == 5
    assert all(s["exchange_valid"] for s in result["samples"])
    assert "c03.domain_age.timeout" in result["samples"][4]["missing_evidence"]
    assert all(
        a["provenance"] == "unverified_header" for a in result["samples"][2]["authentication"]
    )


def test_ingress_override_preserves_existing_auth_references():
    original = AuthenticationSignal(
        id="prior.auth", mechanism="spf", result="pass", provenance="unverified_header"
    )
    finding = Finding(
        id="prior.finding",
        check="prior",
        severity="Suspicious",
        confidence=0.5,
        detail="Synthetic prior context",
        evidence_refs=(original.id,),
    )
    context = CheckContext(
        as_of=DAY, trusted_authentication=(IngressAuthentication(mechanism="spf", result="fail"),)
    )
    result = run_checks(evidence(authentication=(original,), findings=(finding,)), context=context)
    assert result.authentication[0].id == original.id
    assert result.authentication[0].result == "fail"
    assert result.findings[0] == finding
    assert result.findings[1].evidence_refs == (original.id,)


def test_nested_auth_header_is_not_root_provenance():
    data = (
        b'From: a@fablebank.test\nContent-Type: multipart/mixed; boundary="b"\n\n'
        b"--b\nContent-Type: message/rfc822\n\nFrom: a@other.test\n"
        b"Authentication-Results: lab; spf=pass\n\nLab\n--b--\n"
    )
    result = check_eml(data, case_id=CASE, context=CONTEXT)
    assert all(a.result == "not_checked" for a in result.authentication)


def test_maximum_observation_budget_and_rejection():
    observations = tuple(
        DomainAgeObservation(domain=f"a{i}.test", source="lab", status="failed", observed_on=DAY)
        for i in range(201)
    )
    assert len(CheckContext(as_of=DAY, domain_ages=observations[:200]).domain_ages) == 200
    with pytest.raises(ValidationError):
        CheckContext(as_of=DAY, domain_ages=observations)


def test_display_comments_and_groups_remain_unknown():
    for value in ("A (comment) <a@one.test>", "Group: <a@one.test>"):
        assert "c03.sender.unknown" in checked(from_address=value).missing_evidence
