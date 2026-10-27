"""Private worker. Never use the recursive stdlib whole-message MIME parser."""

import base64
import binascii
import hashlib
import json
import quopri
import re
import sys
import time
from email import policy
from email.header import decode_header
from email.message import Message
from email.parser import BytesHeaderParser
from html.parser import HTMLParser
from uuid import UUID

from phishdesk.contracts import EvidenceV1
from phishdesk.contracts.v1 import Attachment, Link
from phishdesk.parsing import ParseLimits, _failure

URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
CHARSETS = {"utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin-1", "windows-1252"}


class Stopped(Exception):
    pass


class Budget:
    def __init__(self, limits: ParseLimits) -> None:
        self.limits = limits
        self.deadline = time.monotonic() + limits.timeout_seconds
        self.missing = ["authentication.not_checked", "sandbox.not_run", "qr.not_run"]
        self.parts = 0
        self.decoded = 0
        self.body = bytearray()
        self.links: list[Link] = []
        self.seen: set[str] = set()
        self.attachments: list[Attachment] = []

    def note(self, code: str) -> None:
        if code not in self.missing and len(self.missing) < 100:
            self.missing.append(code)

    def tick(self) -> None:
        if time.monotonic() >= self.deadline:
            self.note("parser.timeout")
            raise Stopped

    def link(self, value: str) -> None:
        self.tick()
        if not value.lower().startswith(("http://", "https://")):
            return
        if len(value) > 4096:
            self.note("parser.url_bytes")
            return
        if value in self.seen:
            return
        if len(self.links) >= self.limits.links:
            self.note("parser.links")
            return
        self.seen.add(value)
        self.links.append(Link(id=f"link.{len(self.links) + 1}", value=value))

    def text(self, value: str) -> None:
        encoded = value.encode("utf-8", errors="replace")
        remaining = self.limits.body_bytes - len(self.body)
        if len(encoded) > remaining:
            self.note("parser.body_bytes")
        self.body.extend(encoded[:remaining])


class HTMLText(HTMLParser):
    """Inert text projection, not sanitized HTML for browser insertion."""

    def __init__(self, budget: Budget) -> None:
        super().__init__(convert_charrefs=True)
        self.budget = budget
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.budget.tick()
        if tag in {"script", "style"}:
            self.hidden += 1
        for name, value in attrs:
            if name in {"href", "src", "action"} and value:
                self.budget.link(value)
        if tag in {"br", "p", "div", "li"}:
            self.budget.text("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data: str) -> None:
        self.budget.tick()
        if not self.hidden:
            self.budget.text(data)
            for match in URL.finditer(data):
                self.budget.link(match.group())


def decode_text(data: bytes, charset: str, budget: Budget) -> str:
    if charset.lower() not in CHARSETS:
        budget.note("parser.charset_unsupported")
        charset = "utf-8"
    try:
        return data.decode(charset, errors="strict")
    except UnicodeError:
        budget.note("parser.charset_invalid")
        return data.decode(charset, errors="replace")


def header_text(value: str, cap: int, budget: Budget) -> str:
    if len(value) > 4096:
        budget.note("parser.header_value_bytes")
        value = value[:4096]
    try:
        chunks = decode_header(value)
        decoded = "".join(
            decode_text(chunk, charset or "ascii", budget) if isinstance(chunk, bytes) else chunk
            for chunk, charset in chunks
        )
    except (ValueError, LookupError):
        budget.note("parser.header_invalid")
        return ""
    decoded = " ".join(decoded.split())
    if len(decoded) > cap:
        budget.note("parser.header_value_bytes")
    return decoded[:cap]


def headers(raw: bytes, budget: Budget) -> tuple[Message, bytes] | None:
    # Locate separators only within the header ceiling, before any header parsing.
    prefix = raw[: budget.limits.header_bytes + 4]
    separator = re.search(rb"\A\r?\n|\r?\n\r?\n", prefix)
    if separator is None:
        budget.note("parser.headers_missing_or_oversized")
        return None
    block = raw[: separator.start()]
    if len(block) > budget.limits.header_bytes:
        budget.note("parser.header_bytes")
        return None
    lines = block.splitlines()
    if sum(not line.startswith((b" ", b"\t")) for line in lines) > budget.limits.header_count:
        budget.note("parser.header_count")
        return None
    if any(len(line) > 4096 for line in lines):
        budget.note("parser.header_value_bytes")
        return None
    # compat32 avoids headerregistry's complex address grammar on untrusted input.
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(block + b"\n\n")
    if message.defects:
        budget.note("parser.header_invalid")
    if any(
        len(message.get_all(key, [])) > 1
        for key in (
            "Subject",
            "From",
            "Reply-To",
            "Content-Type",
            "Content-Transfer-Encoding",
            "Content-Disposition",
        )
    ):
        budget.note("parser.header_duplicate")
        return None
    return message, raw[separator.end() :]


def decode_payload(raw: bytes, message: Message, budget: Budget) -> bytes | None:
    if len(raw) > budget.limits.part_bytes:
        budget.note("parser.part_bytes")
        return None
    encoding = str(message.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    try:
        if encoding == "base64":
            data = base64.b64decode(re.sub(rb"[\r\n\t ]", b"", raw), validate=True)
        elif encoding == "quoted-printable":
            if re.search(rb"=(?![0-9A-Fa-f]{2}|\r?\n)", raw):
                budget.note("parser.transfer_invalid")
                return None
            data = quopri.decodestring(raw)
        elif encoding in {"7bit", "8bit", "binary"}:
            data = raw
        else:
            budget.note("parser.transfer_unsupported")
            return None
    except (ValueError, binascii.Error):
        budget.note("parser.transfer_invalid")
        return None
    budget.decoded += len(data)
    if budget.decoded > budget.limits.decoded_bytes:
        budget.note("parser.decoded_bytes")
        raise Stopped
    return data


def children(raw: bytes, boundary: str, budget: Budget) -> list[bytes]:
    if (
        not boundary
        or len(boundary) > 70
        or not boundary.isascii()
        or "\n" in boundary
        or "\r" in boundary
    ):
        budget.note("parser.boundary_invalid")
        return []
    marker = re.compile(rb"(?m)^--" + re.escape(boundary.encode("ascii")) + rb"(--)?[ \t]*\r?$")
    parts: list[bytes] = []
    start: int | None = None
    for match in marker.finditer(raw):
        budget.tick()
        if start is not None:
            end = match.start()
            # The CRLF immediately preceding a boundary belongs to the delimiter.
            if raw[max(start, end - 2) : end] == b"\r\n":
                end -= 2
            elif raw[max(start, end - 1) : end] == b"\n":
                end -= 1
            parts.append(raw[start:end])
            if budget.parts + len(parts) > budget.limits.parts:
                budget.note("parser.parts")
                return parts[: budget.limits.parts - budget.parts]
        if match.group(1):
            return parts
        start = match.end() + (1 if raw[match.end() : match.end() + 1] == b"\n" else 0)
    budget.note("parser.boundary_incomplete")
    # Do not parse an unterminated final part as if it were complete.
    return parts


def parse(data: bytes, case_id: UUID, limits: ParseLimits) -> EvidenceV1:
    budget = Budget(limits)
    subject = sender = ""
    reply_to: str | None = None
    stack = [(data, 0)]
    try:
        while stack:
            budget.tick()
            raw, depth = stack.pop()
            if depth > limits.depth:
                budget.note("parser.depth")
                continue
            if budget.parts >= limits.parts:
                budget.note("parser.parts")
                break
            budget.parts += 1
            parsed = headers(raw, budget)
            if parsed is None:
                continue
            message, payload = parsed
            if depth == 0:
                subject = header_text(str(message.get("Subject", "")), 1000, budget)
                sender = header_text(str(message.get("From", "")), 1000, budget)
                reply_to = header_text(str(message.get("Reply-To", "")), 1000, budget) or None
                if not subject:
                    budget.note("message.subject_missing")
                if not sender:
                    budget.note("message.from_missing")
            content_type = message.get_content_type()
            filename = message.get_filename()
            attached = message.get_content_disposition() == "attachment" or filename is not None
            if content_type.startswith("multipart/"):
                if attached:
                    budget.note("parser.multipart_attachment_unsupported")
                    continue
                if depth >= limits.depth:
                    budget.note("parser.depth")
                    continue
                encoding = str(message.get("Content-Transfer-Encoding", "7bit")).lower().strip()
                if encoding not in {"7bit", "8bit", "binary"}:
                    budget.note("parser.multipart_encoding_unsupported")
                    continue
                pieces = children(payload, message.get_boundary() or "", budget)
                # Bound queued siblings as well as visited nodes.
                room = max(0, limits.parts - budget.parts - len(stack))
                if len(pieces) > room:
                    budget.note("parser.parts")
                stack.extend((piece, depth + 1) for piece in reversed(pieces[:room]))
                continue
            if attached or content_type not in {"text/plain", "text/html", "message/rfc822"}:
                if len(budget.attachments) >= limits.attachments:
                    budget.note("parser.attachments")
                    continue
                decoded = decode_payload(payload, message, budget)
                if decoded is None:
                    continue
                name = header_text(filename or "unnamed", 255, budget)
                # A display label only; never use an attacker filename as a path.
                name = name.replace("\\", "/").rsplit("/", 1)[-1] or "unnamed"
                budget.attachments.append(
                    Attachment(
                        id=f"attachment.{len(budget.attachments) + 1}",
                        filename=name,
                        size_bytes=len(decoded),
                        sha256=hashlib.sha256(decoded).hexdigest(),
                    )
                )
                budget.note("attachments.content_not_inspected")
                continue
            decoded = decode_payload(payload, message, budget)
            if decoded is None:
                continue
            if content_type == "message/rfc822":
                stack.append((decoded, depth + 1))
                continue
            remaining = limits.body_bytes - len(budget.body)
            if len(decoded) > remaining:
                budget.note("parser.body_bytes")
                decoded = decoded[:remaining]
            text = decode_text(decoded, message.get_content_charset() or "ascii", budget)
            if budget.body:
                budget.text("\n")
            if content_type == "text/html":
                html = HTMLText(budget)
                html.feed(text)
                html.close()
            else:
                budget.text(text)
                for match in URL.finditer(text):
                    budget.link(match.group())
    except Stopped:
        if "parser.timeout" in budget.missing:
            return _failure(case_id, "parser.timeout")
    if not budget.body:
        budget.note("message.body_missing")
    return EvidenceV1(
        case_id=case_id,
        source="synthetic",
        subject=subject,
        from_address=sender,
        reply_to=reply_to,
        body_text=bytes(budget.body).decode("utf-8", errors="ignore"),
        links=tuple(budget.links),
        attachments=tuple(budget.attachments),
        missing_evidence=tuple(budget.missing),
    )


def main() -> None:
    case_id = UUID(sys.argv[1])
    limits = ParseLimits(**json.loads(sys.argv[2]))
    data = sys.stdin.buffer.read(limits.message_bytes + 1)
    try:
        evidence = (
            parse(data, case_id, limits)
            if len(data) <= limits.message_bytes
            else _failure(case_id, "parser.message_bytes")
        )
    except Exception:
        # No input, exception text or traceback may escape into logs/stderr.
        evidence = _failure(case_id, "parser.malformed")
    sys.stdout.buffer.write(evidence.model_dump_json().encode("utf-8"))


if __name__ == "__main__":
    main()
