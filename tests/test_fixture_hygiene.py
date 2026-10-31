"""Data-safety regression tests: committed test data must be synthetic.

Covers the issue rule: "Use synthetic or appropriately licensed data; no real
private emails, tokens, or credentials in commits/logs."
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from phishdesk_analysis.safety import is_reserved_domain, unreserved_domains

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_FILES = [
    p
    for p in FIXTURES.rglob("*")
    if p.is_file() and p.suffix in {".jsonl", ".json", ".eml", ".txt", ".md"}
]
SECRETS = {
    "AWS key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
    "credential assignment": re.compile(
        r"(?i)\b(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*\S+"
    ),
}


def test_reserved_domain_check_works():
    assert is_reserved_domain("example.com") and is_reserved_domain("mail-admin.test")
    assert is_reserved_domain("acme.example")
    assert not is_reserved_domain("gmail.com") and not is_reserved_domain("monkey.org")


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fixtures_use_only_reserved_domains(path):
    bad = unreserved_domains(path.read_text(encoding="utf-8"))
    assert not bad, f"real-looking domains in {path.name}: {bad}"


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fixtures_contain_no_secrets(path):
    text = path.read_text(encoding="utf-8")
    found = [name for name, pattern in SECRETS.items() if pattern.search(text)]
    assert not found, f"possible secrets in {path.name}: {found}"


def test_no_raw_public_data_is_tracked_by_git():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not running inside a git checkout")
    tracked = subprocess.run(
        ["git", "ls-files", "data/raw/public", "*.mbox"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert not tracked, f"raw public data is committed: {tracked[:5]}"
