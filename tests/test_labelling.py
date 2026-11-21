"""Tests for the terminal labelling helpers. All emails are synthetic."""

import csv
from email.message import EmailMessage

import pytest

from phishdesk_analysis.corpus import WORK_COLUMNS
from phishdesk_analysis.labelling import (
    WorkSheet,
    apply_label,
    apply_skip,
    check_reason,
    content_key,
    defang,
    describe_email,
    is_done,
    missing_key_tactics,
    parse_tactics,
    safe_text,
)
from phishdesk_analysis.records import Category, Confidence, Tactic


def make_sheet(tmp_path, subjects):
    path = tmp_path / "nazario.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=WORK_COLUMNS)
        writer.writeheader()
        for i, subject in enumerate(subjects):
            writer.writerow(
                {c: "" for c in WORK_COLUMNS}
                | {
                    "id": f"nazario-2099-{i:04d}",
                    "file": f"nazario-2099-{i:04d}.eml",
                    "subject": subject,
                    "is_phishing": "true",
                    "language": "en",
                }
            )
    return path


def test_parse_tactics_letters():
    assert parse_tactics("ui l") == [Tactic.URGENCY, Tactic.IMPERSONATION, Tactic.LINK_LURE]
    assert parse_tactics("") == []
    assert parse_tactics("uu") == [Tactic.URGENCY]
    with pytest.raises(ValueError, match="unknown tactic"):
        parse_tactics("x")


def test_apply_label_derives_is_phishing():
    row = {"is_phishing": "true"}
    apply_label(row, Category.LEGIT_URGENT, [Tactic.URGENCY], Confidence.HIGH, "p2", " ok ")
    assert row["is_phishing"] == "false" and row["category"] == "legit_urgent"
    assert row["tactics"] == "urgency" and row["reason"] == "ok"
    apply_label(row, Category.CREDENTIAL, [], Confidence.LOW, "p2", "")
    assert row["is_phishing"] == "true" and row["label_confidence"] == "low"


def test_skip_is_remembered_but_not_exported_as_label():
    row = {"category": "credential"}
    apply_skip(row, "p2", "newsletter")
    assert row["category"] == "" and row["reason"].startswith("skip:")
    assert is_done(row)


def test_missing_key_tactics_only_for_phishing():
    assert missing_key_tactics(Category.CREDENTIAL, [Tactic.LINK_LURE])
    assert not missing_key_tactics(Category.CREDENTIAL, [Tactic.URGENCY])
    assert not missing_key_tactics(Category.BENIGN, [])


@pytest.mark.parametrize("reason", ["sent from evil.test", "user@x", "see invoice.pdf"])
def test_reason_must_not_name_domains_or_addresses(reason):
    assert check_reason(reason) is not None


def test_plain_reason_is_accepted():
    assert check_reason("fake IT sender, outside login link") is None


def test_worksheet_saves_and_queues(tmp_path):
    path = make_sheet(tmp_path, ["Verify mailbox", "Invoice overdue", "Team lunch"])
    sheet = WorkSheet(path)
    assert sheet.queue() == [0, 1, 2]
    assert sheet.queue(search="INVOICE") == [1]
    apply_label(sheet.rows[0], Category.CREDENTIAL, [], Confidence.HIGH, "p2", "")
    apply_skip(sheet.rows[2], "p2", "personal")
    sheet.save()
    reloaded = WorkSheet(path)
    assert reloaded.queue() == [1]
    assert reloaded.queue(include_done=True) == [0, 1, 2]
    assert reloaded.counts()["credential"] == 1 and reloaded.skipped() == 1
    assert reloaded.fieldnames == WORK_COLUMNS
    assert not list(tmp_path.glob("*.tmp"))


def test_worksheet_rejects_wrong_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("id,subject\nx,y\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing columns"):
        WorkSheet(path)


def test_safe_text_removes_terminal_control_and_bidi_characters():
    hostile = "ok\x1b[2J\x07 text\u202egnp.exe\n"
    assert safe_text(hostile) == "ok[2J textgnp.exe\n"


def test_defang_makes_links_unclickable():
    assert defang("https://login.evil.test/a.b") == "hxxps://login[.]evil[.]test/a.b"


def test_describe_email_is_safe_and_helpful():
    msg = EmailMessage()
    msg["From"] = "IT Desk <it@corp-it.test>"
    msg["Reply-To"] = "verify@other.test"
    msg["Subject"] = "Mailbox \x1b[31mfull"
    msg.set_content("Verify now: https://login.other.test/x\n")
    msg.add_attachment(b"x", maintype="text", subtype="html", filename="form.html")
    text = describe_email(msg.as_bytes())
    assert "\x1b" not in text
    assert "hxxps://login[.]other[.]test/x" in text and "https://" not in text
    assert "form.html" in text
    assert "Reply-To domain differs" in text and "links point to domains other" in text


def test_content_key_ignores_formatting_but_not_content():
    def eml(subject, body, sender="a@corp.test"):
        msg = EmailMessage()
        msg["From"] = sender
        msg["Subject"] = subject
        msg.set_content(body)
        return msg.as_bytes()

    same = content_key(eml("Lunch", "See you at noon."))
    assert same == content_key(eml("lunch", "See   you at noon!", sender="b@corp.test"))
    assert same != content_key(eml("Lunch", "See you at one."))
