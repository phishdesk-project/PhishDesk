"""Synthetic parser regression tests. Never visit extracted URL strings."""

import hashlib
import json
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest

from phishdesk.contracts import EvidenceV1
from phishdesk.parsing import ParseLimits, parse_eml, parse_eml_file
from phishdesk.parsing._worker import Budget, parse

CASE = UUID("00000000-0000-4000-8000-000000000008")
FIXTURES = Path(__file__).parent / "fixtures" / "mime"
SAMPLES = sorted(FIXTURES.glob("*.eml"))


def mail(body=b"Lab", extra=b""):
    return b"From: lab@fablebank.test\r\nSubject: Lab\r\n" + extra + b"\r\n" + body


def local(data, **changes):
    return parse(data, CASE, replace(ParseLimits(), **changes))


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.stem)
def test_twenty_fixtures_through_public_worker(path):
    evidence = parse_eml_file(path, case_id=CASE)
    assert len(SAMPLES) == 20
    assert EvidenceV1.model_validate_json(evidence.model_dump_json()) == evidence
    assert evidence.case_id == CASE and evidence.source == "synthetic"
    assert evidence.authentication == () and evidence.findings == ()
    assert evidence.sandbox_state == "not_run"
    assert "qr.not_run" in evidence.missing_evidence
    assert not any(
        s in evidence.missing_evidence
        for s in ("parser.worker_failed", "parser.timeout", "parser.malformed")
    )


def sample(prefix):
    return local(next(FIXTURES.glob(prefix + "*.eml")).read_bytes())


def test_fields_and_decoding():
    assert sample("01").from_address == "FableBank Lab <lab@fablebank.test>"
    assert sample("02").body_text.startswith("Invented café")
    assert sample("03").body_text == "Lab text"
    assert sample("04").body_text == "Lab café"
    assert sample("09").subject == "Lab café"
    assert sample("10").reply_to == "support@fablebank.test"
    assert "Forwarded lab" in sample("12").body_text
    assert sample("11").authentication == ()
    assert sample("20").body_text == "Synthetic body without identity"


def test_multipart_html_and_hashes():
    html = sample("05")
    assert "secret_script" not in html.body_text
    assert "<" not in html.body_text
    assert html.links[0].value == "https://fablebank.test/login?a=1&b=2"
    assert "Plain lab" in sample("06").body_text and "HTML lab" in sample("06").body_text
    attachment = sample("07").attachments[0]
    assert attachment.filename == "lab.txt" and attachment.size_bytes == 3
    assert attachment.sha256 == hashlib.sha256(b"lab").hexdigest()
    assert sample("08").attachments[0].filename == "qr.png"
    assert sample("18").attachments[0].filename == "lab.txt"
    assert len(sample("19").links) == 2


@pytest.mark.parametrize(
    ("prefix", "state"),
    [
        ("13", "parser.boundary_invalid"),
        ("14", "parser.boundary_incomplete"),
        ("15", "parser.transfer_invalid"),
        ("16", "parser.charset_unsupported"),
        ("17", "parser.header_duplicate"),
        ("20", "message.from_missing"),
    ],
)
def test_explicit_failure_states(prefix, state):
    assert state in sample(prefix).missing_evidence


def test_message_size_rejected_before_worker(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("oversized input must not reach worker")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert (
        "parser.message_bytes"
        in parse_eml(
            b"x" * 17, case_id=CASE, limits=replace(ParseLimits(), message_bytes=16)
        ).missing_evidence
    )


def test_file_read_size_and_missing(tmp_path):
    path = tmp_path / "large.eml"
    path.write_bytes(b"x" * 1024)
    assert (
        "parser.message_bytes"
        in parse_eml_file(
            path, case_id=CASE, limits=replace(ParseLimits(), message_bytes=10)
        ).missing_evidence
    )
    assert (
        "parser.file_unavailable"
        in parse_eml_file(tmp_path / "missing", case_id=CASE).missing_evidence
    )


@pytest.mark.parametrize(
    ("data", "limits", "state"),
    [
        (mail(), {"header_bytes": 10}, "parser.headers_missing_or_oversized"),
        (mail(), {"header_count": 1}, "parser.header_count"),
        (mail(b"abcdef"), {"part_bytes": 5}, "parser.part_bytes"),
        (mail(b"abcdef"), {"body_bytes": 5}, "parser.body_bytes"),
        (mail(b"abcdef"), {"decoded_bytes": 5}, "parser.decoded_bytes"),
        (mail(b"https://a.test https://b.test"), {"links": 1}, "parser.links"),
        (mail(b"https://a.test/" + b"x" * 4100), {}, "parser.url_bytes"),
        (
            mail(b"=XX", b"Content-Transfer-Encoding: quoted-printable\r\n"),
            {},
            "parser.transfer_invalid",
        ),
        (mail(b"Lab", b"Content-Transfer-Encoding: gzip\r\n"), {}, "parser.transfer_unsupported"),
        (
            mail(b"\xff", b"Content-Type: text/plain; charset=utf-8\r\n"),
            {},
            "parser.charset_invalid",
        ),
    ],
)
def test_resource_and_decoding_limits(data, limits, state):
    result = local(data, **limits)
    assert state in result.missing_evidence
    assert len(result.body_text.encode()) <= limits.get("body_bytes", 100_000)


def mixed(parts):
    return mail(
        b"".join(b"--b\r\n" + part + b"\r\n" for part in parts) + b"--b--\r\n",
        b'Content-Type: multipart/mixed; boundary="b"\r\n',
    )


def test_part_and_attachment_limits():
    result = local(mixed([mail()] * 10), parts=3)
    assert "parser.parts" in result.missing_evidence
    assert result.body_text.count("Lab") == 2
    attachment = mail(b"lab", b'Content-Disposition: attachment; filename="lab.txt"\r\n')
    result = local(mixed([attachment] * 5), attachments=2)
    assert len(result.attachments) == 2 and "parser.attachments" in result.missing_evidence


def test_deep_nesting_is_stopped_before_recursive_parse():
    data = mail()
    for _ in range(100):
        data = mail(data, b"Content-Type: message/rfc822\r\n")
    result = local(data, depth=3)
    assert "parser.depth" in result.missing_evidence
    assert result.body_text == ""
    assert "parser.depth" in parse_eml(data, case_id=CASE).missing_evidence


def test_nested_malformed_multipart():
    nested = mixed([mail(b"broken", b"Content-Type: multipart/mixed; boundary=missing\r\n")])
    assert "parser.boundary_incomplete" in local(nested).missing_evidence


def test_deep_multipart_and_exact_part_ceiling():
    data = mail()
    for index in range(50):
        boundary = f"level{index}".encode()
        data = mail(
            b"--" + boundary + b"\r\n" + data + b"\r\n--" + boundary + b"--\r\n",
            b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n",
        )
    assert "parser.depth" in local(data, depth=3).missing_evidence
    exact = local(mixed([mail(), mail()]), parts=3)
    assert "parser.parts" not in exact.missing_evidence
    assert exact.body_text.count("Lab") == 2


def test_attachment_omission_never_presents_partial_hash():
    extra = b'Content-Disposition: attachment; filename="lab.txt"\r\n'
    oversized = local(mixed([mail(b"abcdef", extra)]), part_bytes=5)
    assert oversized.attachments == () and "parser.part_bytes" in oversized.missing_evidence
    invalid = local(mixed([mail(b"%%%", extra + b"Content-Transfer-Encoding: base64\r\n")]))
    assert invalid.attachments == () and "parser.transfer_invalid" in invalid.missing_evidence
    aggregate = local(mixed([mail(b"abc", extra)] * 3), decoded_bytes=5)
    assert len(aggregate.attachments) == 1
    assert aggregate.attachments[0].sha256 == hashlib.sha256(b"abc").hexdigest()
    assert "parser.decoded_bytes" in aggregate.missing_evidence


def test_binary_attachment_preserves_its_own_final_crlf():
    payload = b"lab\x00\xff\r\n"
    extra = b'Content-Disposition: attachment; filename="binary.bin"\r\n'
    attachment = local(mixed([mail(payload, extra)])).attachments[0]
    assert attachment.size_bytes == len(payload)
    assert attachment.sha256 == hashlib.sha256(payload).hexdigest()


def test_real_worker_timeout():
    result = parse_eml(mail(), case_id=CASE, limits=replace(ParseLimits(), timeout_seconds=0.001))
    assert result.missing_evidence[0] == "parser.timeout"
    assert result.body_text == ""


def test_cooperative_deadline(monkeypatch):
    budget = Budget(ParseLimits())
    monkeypatch.setattr("phishdesk.parsing._worker.time.monotonic", lambda: budget.deadline + 1)
    from phishdesk.parsing._worker import Stopped

    with pytest.raises(Stopped):
        budget.tick()
    assert "parser.timeout" in budget.missing


def test_worker_failure_is_static(monkeypatch, caplog):
    canary = "PRIVATE_CONTENT_CANARY"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            [], 1, stdout=canary.encode(), stderr=canary.encode()
        ),
    )
    result = parse_eml(mail(canary.encode()), case_id=CASE)
    assert canary not in result.model_dump_json() + caplog.text
    assert "parser.worker_failed" in result.missing_evidence


def test_offline_worker_core_and_inert_content(monkeypatch, caplog, tmp_path):
    def deny(*args, **kwargs):
        raise AssertionError("parser must not use network")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    before = set(tmp_path.iterdir())
    result = local(
        mail(
            b'<script>PRIVATE_CONTENT_CANARY</script><img src="https://fablebank.test/pixel">',
            b"Content-Type: text/html\r\n",
        )
    )
    assert len(result.links) == 1 and "PRIVATE_CONTENT_CANARY" not in result.body_text + caplog.text
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("depth", 1000),
        ("parts", 0),
        ("message_bytes", -1),
        ("links", True),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", float("inf")),
    ],
)
def test_limits_cannot_disable_safeguards(field, value):
    with pytest.raises(ValueError):
        replace(ParseLimits(), **{field: value})


def test_private_worker_rechecks_size():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "phishdesk.parsing._worker",
            str(CASE),
            json.dumps({"message_bytes": 10}),
        ],
        input=b"x" * 100,
        capture_output=True,
        check=True,
    )
    assert "parser.message_bytes" in EvidenceV1.model_validate_json(result.stdout).missing_evidence
    assert result.stderr == b""
