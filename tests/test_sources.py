"""Tests for the sources register, verified downloads and safe preparation. No network used."""

import hashlib
import io
import json
import mailbox
import tarfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishdesk_analysis.records import KNOWN_SOURCES
from phishdesk_analysis.sources import (
    USABLE_STATUSES,
    SourceError,
    SourceFile,
    download_file,
    download_source,
    load_register,
    safe_extract_tar,
    split_mbox,
    write_recorded_hashes,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "data" / "sources.json"
CONTENT = b"synthetic test file\n"
CONTENT_SHA = hashlib.sha256(CONTENT).hexdigest()


def fake_opener(payload: bytes = CONTENT):
    def opener(url: str):
        assert url.startswith("https://")
        return io.BytesIO(payload)

    return opener


# --- register -------------------------------------------------------------


def test_register_is_valid():
    register = load_register(REGISTER)
    assert {s.id for s in register.sources} >= {"synthetic", "nazario"}


def test_known_sources_match_register():
    register = load_register(REGISTER)
    allowed = {s.id for s in register.sources if s.status != "do-not-use"}
    assert allowed == KNOWN_SOURCES


def test_unlicensed_sources_are_not_redistributable():
    for source in load_register(REGISTER).sources:
        if source.status in {"approved-local", "pending"}:
            assert not source.redistributable, source.id


def test_usable_public_sources_have_files_and_decision():
    for source in load_register(REGISTER).sources:
        if source.status in USABLE_STATUSES and source.id != "synthetic":
            assert source.files, source.id
            assert source.attribution, source.id


# --- downloads ------------------------------------------------------------


def test_download_with_matching_hash_is_kept(tmp_path):
    f = SourceFile(name="sample.bin", url="https://example.com/sample.bin", sha256=CONTENT_SHA)
    assert download_file(f, tmp_path, opener=fake_opener()) == CONTENT_SHA
    assert (tmp_path / "sample.bin").read_bytes() == CONTENT


def test_hash_mismatch_is_rejected_and_nothing_is_left(tmp_path):
    f = SourceFile(name="sample.bin", url="https://example.com/sample.bin", sha256=CONTENT_SHA)
    with pytest.raises(SourceError, match="mismatch"):
        download_file(f, tmp_path, opener=fake_opener(b"tampered\n"))
    assert list(tmp_path.iterdir()) == []


def test_missing_hash_is_refused_without_record(tmp_path):
    f = SourceFile(name="sample.bin", url="https://example.com/sample.bin")
    with pytest.raises(SourceError, match="no expected sha256"):
        download_file(f, tmp_path, opener=fake_opener())
    assert list(tmp_path.iterdir()) == []


def test_record_mode_keeps_file_and_returns_hash(tmp_path):
    f = SourceFile(name="sample.bin", url="https://example.com/sample.bin")
    assert download_file(f, tmp_path, opener=fake_opener(), record=True) == CONTENT_SHA
    assert (tmp_path / "sample.bin").exists()


def test_existing_verified_file_is_not_downloaded_again(tmp_path):
    (tmp_path / "sample.bin").write_bytes(CONTENT)
    f = SourceFile(name="sample.bin", url="https://example.com/sample.bin", sha256=CONTENT_SHA)

    def failing_opener(url):
        raise AssertionError("should not download")

    assert download_file(f, tmp_path, opener=failing_opener) == CONTENT_SHA


def test_http_urls_are_rejected():
    with pytest.raises(ValueError):
        SourceFile(name="x", url="http://example.com/x")


def test_pending_source_cannot_be_downloaded(tmp_path):
    register = load_register(REGISTER)
    pending = [s.id for s in register.sources if s.status == "pending"]
    if not pending:
        pytest.skip("no pending sources in the register")
    with pytest.raises(SourceError, match="must approve"):
        download_source(register, pending[0], tmp_path, opener=fake_opener())


def test_record_writes_only_empty_hashes(tmp_path):
    reg = tmp_path / "sources.json"
    reg.write_text(
        json.dumps(
            {
                "version": 1,
                "sources": [
                    {
                        "id": "demo",
                        "files": [
                            {"name": "a", "url": "https://example.com/a", "sha256": None},
                            {"name": "b", "url": "https://example.com/b", "sha256": "1" * 64},
                        ],
                    }
                ],
            }
        )
    )
    write_recorded_hashes(reg, "demo", {"a": "a" * 64, "b": "b" * 64})
    files = json.loads(reg.read_text())["sources"][0]["files"]
    assert files[0]["sha256"] == "a" * 64
    assert files[1]["sha256"] == "1" * 64


# --- preparation ----------------------------------------------------------


def make_mbox(path: Path, count: int) -> None:
    box = mailbox.mbox(str(path))
    for i in range(count):
        msg = EmailMessage()
        msg["From"] = f"sender{i}@mail-admin.test"
        msg["To"] = "user@example.com"
        msg["Subject"] = f"Synthetic message {i}"
        msg.set_content(f"Body {i}")
        box.add(msg)
    box.flush()
    box.close()


def test_split_mbox_is_deterministic(tmp_path):
    mbox_path = tmp_path / "phishing-2099"
    make_mbox(mbox_path, 3)
    first = split_mbox(mbox_path, tmp_path / "out1", prefix="nazario-2099")
    second = split_mbox(mbox_path, tmp_path / "out2", prefix="nazario-2099")
    assert [r[0] for r in first] == ["nazario-2099-0000", "nazario-2099-0001", "nazario-2099-0002"]
    assert first == second
    eml = (tmp_path / "out1" / "nazario-2099-0001.eml").read_bytes()
    assert b"Synthetic message 1" in eml
    assert hashlib.sha256(eml).hexdigest() == first[1][2]


def make_tar(path: Path, members: list[tarfile.TarInfo], data: bytes = b"x") -> None:
    with tarfile.open(path, "w:bz2") as tar:
        for info in members:
            if info.isfile():
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                tar.addfile(info)


def test_safe_extract_extracts_regular_files(tmp_path):
    tar_path = tmp_path / "ok.tar.bz2"
    make_tar(tar_path, [tarfile.TarInfo("easy_ham/00001.abc"), tarfile.TarInfo("easy_ham/cmds")])
    extracted = safe_extract_tar(tar_path, tmp_path / "out")
    assert sorted(p.name for p in extracted) == ["00001.abc", "cmds"]


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil.txt", "easy_ham/../../evil.txt"])
def test_safe_extract_rejects_path_traversal(tmp_path, name):
    tar_path = tmp_path / "bad.tar.bz2"
    make_tar(tar_path, [tarfile.TarInfo(name)])
    with pytest.raises(SourceError, match="unsafe path"):
        safe_extract_tar(tar_path, tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


def test_safe_extract_rejects_symlinks(tmp_path):
    link = tarfile.TarInfo("easy_ham/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    tar_path = tmp_path / "link.tar.bz2"
    make_tar(tar_path, [link])
    with pytest.raises(SourceError, match="unsupported member"):
        safe_extract_tar(tar_path, tmp_path / "out")
