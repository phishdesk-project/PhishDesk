"""Helpers for the terminal labelling tool (scripts/label_cli.py).

The tool edits a local work sheet (data/labels/work/<name>.csv) in place, one email
at a time, saving after every change. Email content is shown as plain text only:
control characters are removed and links are defanged so nothing is clickable.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import tempfile
from collections import Counter
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path

from phishdesk_analysis.corpus import normalise, parse_email, plain_text
from phishdesk_analysis.records import PHISHING_CATEGORIES, Category, Confidence, Tactic

CATEGORY_KEYS: dict[str, Category] = {
    "1": Category.CREDENTIAL,
    "2": Category.PAYMENT,
    "3": Category.IMPERSONATION,
    "4": Category.URGENCY,
    "5": Category.BENIGN,
    "6": Category.LEGIT_URGENT,
}
TACTIC_KEYS: dict[str, Tactic] = {
    "u": Tactic.URGENCY,
    "i": Tactic.IMPERSONATION,
    "l": Tactic.LINK_LURE,
    "a": Tactic.ATTACHMENT_LURE,
    "r": Tactic.QR_CODE,
}
CONFIDENCE_KEYS: dict[str, Confidence] = {
    "": Confidence.HIGH,
    "h": Confidence.HIGH,
    "m": Confidence.MEDIUM,
    "l": Confidence.LOW,
}
SKIP_PREFIX = "skip:"

# C0/C1 control characters (except tab and newline) and bidirectional overrides,
# which a hostile email could use to rewrite or hide terminal output.
_UNSAFE_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_DOMAIN_LIKE = re.compile(r"\b[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")
_LINK = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


def safe_text(text: str) -> str:
    return _UNSAFE_CHARS.sub("", text)


def defang(url: str) -> str:
    """hxxps://example[.]com/path: readable but not clickable."""
    scheme, _, rest = url.partition("://")
    host, slash, path = rest.partition("/")
    return f"{scheme.replace('tt', 'xx', 1)}://{host.replace('.', '[.]')}{slash}{path}"


def defang_all(text: str) -> str:
    return _LINK.sub(lambda m: defang(m.group(0)), text)


# --- work sheet ------------------------------------------------------------


class WorkSheet:
    """A labelling CSV kept in memory and saved atomically after each change."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            self.fieldnames = list(reader.fieldnames or [])
            self.rows: list[dict[str, str]] = [dict(r) for r in reader]
        required = {"id", "file", "category", "tactics", "label_confidence", "label_by", "reason"}
        missing = required - set(self.fieldnames)
        if missing:
            raise ValueError(f"{path.name} is missing columns: {sorted(missing)}")

    def save(self) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)
        os.replace(tmp, self.path)

    def counts(self) -> Counter[str]:
        return Counter(r["category"] for r in self.rows if r.get("category"))

    def skipped(self) -> int:
        return sum(1 for r in self.rows if is_skipped(r))

    def queue(
        self,
        search: str | None = None,
        include_done: bool = False,
        ids: set[str] | None = None,
    ) -> list[int]:
        """Row positions to show: unlabelled rows, optionally filtered by subject or id."""
        needle = search.lower() if search else None
        out = []
        for i, row in enumerate(self.rows):
            if ids is not None and row["id"] not in ids:
                continue
            if not include_done and is_done(row):
                continue
            if needle and needle not in (row.get("subject") or "").lower():
                continue
            out.append(i)
        return out


def is_skipped(row: dict[str, str]) -> bool:
    return (row.get("reason") or "").startswith(SKIP_PREFIX) and not row.get("category")


def is_done(row: dict[str, str]) -> bool:
    return bool(row.get("category")) or is_skipped(row)


def sheet_source(sheet_name: str) -> str:
    """'nazario' -> nazario, 'enron-urgent' -> enron, 'review-person1-enron' -> enron."""
    parts = sheet_name.split("-")
    if parts[0] == "review" and len(parts) >= 3:
        return parts[2]
    return parts[0]


# --- applying labels -------------------------------------------------------


def parse_tactics(keys: str) -> list[Tactic]:
    tactics: list[Tactic] = []
    for key in keys.replace(",", "").replace(" ", "").lower():
        if key not in TACTIC_KEYS:
            raise ValueError(f"unknown tactic key '{key}' (use {', '.join(TACTIC_KEYS)})")
        if TACTIC_KEYS[key] not in tactics:
            tactics.append(TACTIC_KEYS[key])
    return tactics


def check_reason(reason: str) -> str | None:
    """Return a problem description if the reason names a domain or address."""
    if "@" in reason or _DOMAIN_LIKE.search(reason):
        return "keep reasons free of addresses, domains and file names"
    return None


def apply_label(
    row: dict[str, str],
    category: Category,
    tactics: list[Tactic],
    confidence: Confidence,
    label_by: str,
    reason: str,
) -> None:
    """Fill a row. is_phishing is derived from the category so they can't disagree."""
    row["category"] = category.value
    row["is_phishing"] = "true" if category in PHISHING_CATEGORIES else "false"
    row["tactics"] = ",".join(t.value for t in tactics)
    row["label_confidence"] = confidence.value
    row["label_by"] = label_by
    row["reason"] = reason.strip()
    if not row.get("language"):
        row["language"] = "en"


def apply_skip(row: dict[str, str], label_by: str, why: str) -> None:
    row["category"] = ""
    row["tactics"] = ""
    row["label_confidence"] = ""
    row["label_by"] = label_by
    row["reason"] = f"{SKIP_PREFIX} {why.strip() or 'not usable'}"


def missing_key_tactics(category: Category, tactics: list[Tactic]) -> bool:
    """Phishing labelled without urgency or impersonation: worth a second look."""
    return category in PHISHING_CATEGORIES and not (
        {Tactic.URGENCY, Tactic.IMPERSONATION} & set(tactics)
    )


# --- showing an email ------------------------------------------------------


def _domain(address_header: str) -> str:
    return parseaddr(address_header)[1].rpartition("@")[2].lower()


def _header(msg: EmailMessage, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    return " ".join(str(value).split()) if value is not None else ""


def _raw_text_parts(msg: EmailMessage) -> str:
    texts = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        try:
            texts.append(str(part.get_content()))
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                texts.append(payload.decode("utf-8", "replace"))
    return "\n".join(texts)


def describe_email(data: bytes, max_chars: int = 2500) -> str:
    """Readable, safe summary: headers, body text, defanged links, attachments, hints."""
    msg = parse_email(data)
    from_h, reply_h = _header(msg, "From"), _header(msg, "Reply-To")
    lines = [
        f"From:     {from_h}",
        f"Reply-To: {reply_h or '-'}",
        f"To:       {_header(msg, 'To')}",
        f"Subject:  {_header(msg, 'Subject')}",
        f"Date:     {_header(msg, 'Date')}",
        "-" * 70,
    ]
    body = defang_all(plain_text(msg))
    subject = _header(msg, "Subject")
    if body.startswith(subject):
        body = body[len(subject) :].strip()
    lines.append(body[:max_chars] + (" [...more: press m]" if len(body) > max_chars else ""))
    lines.append("-" * 70)

    links = sorted(set(_LINK.findall(_raw_text_parts(msg))))
    lines.append(f"Links ({len(links)}):")
    lines += [f"  {defang(u)[:110]}" for u in links[:10]]
    if len(links) > 10:
        lines.append(f"  ... {len(links) - 10} more")
    attachments = [p.get_filename() or "(no name)" for p in msg.iter_attachments()]
    lines.append(f"Attachments: {', '.join(attachments) if attachments else 'none'}")

    hints = []
    from_domain = _domain(from_h)
    if reply_h and _domain(reply_h) and _domain(reply_h) != from_domain:
        hints.append("Reply-To domain differs from From domain")
    link_domains = {u.split("/")[2].lower() for u in links if u.count("/") >= 2}
    if from_domain and link_domains and not any(from_domain in d for d in link_domains):
        hints.append("links point to domains other than the sender's")
    if attachments:
        hints.append("has attachments (judge by name only, never open them)")
    lines.append("Hints: " + ("; ".join(hints) if hints else "none"))
    return safe_text("\n".join(lines))


def content_key(data: bytes) -> str:
    """Same subject and text (ignoring case, spacing and punctuation) -> same key.

    Matches the exact-duplicate rule used by build_dataset.py, so a duplicate
    skipped here would have been dropped from the dataset anyway.
    """
    return hashlib.sha256(normalise(plain_text(parse_email(data))).encode()).hexdigest()


def full_body(data: bytes) -> str:
    return safe_text(defang_all(plain_text(parse_email(data))))
