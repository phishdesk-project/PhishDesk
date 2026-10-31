"""Sources register, verified downloads and safe preparation of public email data.

The register lives in data/sources.json. Raw public data is written under
data/raw/public/, which is gitignored and never committed.
"""

from __future__ import annotations

import csv
import hashlib
import json
import mailbox
import shutil
import tarfile
import urllib.request
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["approved", "approved-local", "pending", "do-not-use"]
USABLE_STATUSES: frozenset[str] = frozenset({"approved", "approved-local"})
CHUNK = 1024 * 1024


class SourceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    url: str = Field(pattern=r"^https://")
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=1)
    homepage: str | None = None
    licence: str = Field(min_length=1)
    redistributable: bool
    status: Status
    contains: str = Field(min_length=1)
    attribution: str | None = None
    notes: str = ""
    decided_by: str | None = None
    files: list[SourceFile] = Field(default_factory=list)


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    sources: list[Source]

    def get(self, source_id: str) -> Source:
        for source in self.sources:
            if source.id == source_id:
                return source
        raise KeyError(f"source '{source_id}' is not in the register")


class SourceError(RuntimeError):
    """Raised when a source cannot be downloaded or prepared safely."""


def load_register(path: str | Path) -> Register:
    return Register.model_validate_json(Path(path).read_text(encoding="utf-8"))


def sha256_of(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_opener(url: str) -> BinaryIO:
    return cast(BinaryIO, urllib.request.urlopen(url, timeout=120))  # noqa: S310 (https only)


Opener = Callable[[str], BinaryIO]


def download_file(
    file: SourceFile,
    dest_dir: Path,
    opener: Opener = _default_opener,
    record: bool = False,
) -> str:
    """Download one file and check its SHA-256. Returns the digest.

    - Expected hash set: the file is kept only if it matches.
    - No expected hash: refused unless record=True (first download by a maintainer).
    - A file already present with the expected hash is not downloaded again.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / file.name
    if file.sha256 and dest.exists() and sha256_of(dest) == file.sha256:
        return file.sha256

    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    try:
        with opener(file.url) as response, open(part, "wb") as out:
            for chunk in iter(lambda: response.read(CHUNK), b""):
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        part.unlink(missing_ok=True)
        raise SourceError(f"download failed for {file.url}: {exc}") from exc

    actual = digest.hexdigest()
    if file.sha256 is None and not record:
        part.unlink()
        raise SourceError(
            f"{file.name} has no expected sha256 in the register (downloaded: {actual}). "
            "A maintainer must run with --record once and commit the hash."
        )
    if file.sha256 is not None and actual != file.sha256:
        part.unlink()
        raise SourceError(f"{file.name}: sha256 mismatch (expected {file.sha256}, got {actual})")
    part.replace(dest)
    return actual


def download_source(
    register: Register,
    source_id: str,
    raw_root: Path,
    opener: Opener = _default_opener,
    record: bool = False,
) -> dict[str, str]:
    """Download every file of an approved source. Returns {file name: sha256}."""
    source = register.get(source_id)
    if source.status not in USABLE_STATUSES:
        raise SourceError(
            f"source '{source_id}' has status '{source.status}'; "
            "both owners must approve it in data/sources.json first"
        )
    if not source.files:
        raise SourceError(f"source '{source_id}' has no downloadable files")
    dest_dir = raw_root / source_id
    return {f.name: download_file(f, dest_dir, opener, record) for f in source.files}


def write_recorded_hashes(register_path: Path, source_id: str, hashes: dict[str, str]) -> None:
    """Fill in sha256 values that are still empty. Existing hashes are never overwritten."""
    data = json.loads(register_path.read_text(encoding="utf-8"))
    for source in data["sources"]:
        if source["id"] != source_id:
            continue
        for f in source["files"]:
            if f.get("sha256") is None and f["name"] in hashes:
                f["sha256"] = hashes[f["name"]]
    register_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


IndexRow = tuple[str, str, str]  # (id, relative file path, sha256)


def write_index(rows: list[IndexRow], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "file", "sha256"])
        writer.writerows(rows)


def split_mbox(mbox_path: Path, out_dir: Path, prefix: str) -> list[IndexRow]:
    """Split an mbox file into one .eml per message, keeping the original bytes.

    IDs follow file order: <prefix>-0000, <prefix>-0001, ...
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    box = mailbox.mbox(str(mbox_path), create=False)
    rows: list[IndexRow] = []
    try:
        for i, key in enumerate(box.keys()):
            msg_id = f"{prefix}-{i:04d}"
            data = box.get_bytes(key)
            target = out_dir / f"{msg_id}.eml"
            target.write_bytes(data)
            rows.append((msg_id, target.name, hashlib.sha256(data).hexdigest()))
    finally:
        box.close()
    return rows


def safe_extract_tar(tar_path: Path, out_dir: Path) -> list[Path]:
    """Extract regular files only; reject absolute paths, '..', links and devices."""
    out_dir.mkdir(parents=True, exist_ok=True)
    root = out_dir.resolve()
    extracted: list[Path] = []
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise SourceError(f"unsafe path in {tar_path.name}: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise SourceError(f"unsupported member type in {tar_path.name}: {member.name}")
            target = (root / Path(*name.parts)).resolve()
            if not target.is_relative_to(root):
                raise SourceError(f"unsafe path in {tar_path.name}: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise SourceError(f"cannot read {member.name} in {tar_path.name}")
            with source, open(target, "wb") as out:
                shutil.copyfileobj(source, out, CHUNK)
            extracted.append(target)
    return extracted
