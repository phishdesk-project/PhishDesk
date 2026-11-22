"""Build the labelled corpus: label sheets, safe label export, joining, dedup and splits.

Workflow
1. make_label_sheet: local CSV (real senders/subjects) for labelling in a spreadsheet.
2. export_labels: keep only safe columns (ids, hashes, labels, hashed sender group).
   The exported file is committed; the work sheet never is.
3. build_records: join committed labels with hash-verified local emails and
   synthetic records into EmailRecords.
4. dedupe + split_records: drop exact duplicates, group near-duplicates, and make
   a group-aware, per-category 70/15/15 split.
"""

from __future__ import annotations

import csv
import email
import hashlib
import html
import json
import random
import re
import tarfile
from collections import Counter, defaultdict
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from phishdesk_analysis.records import (
    PHISHING_CATEGORIES,
    Category,
    Confidence,
    EmailRecord,
    Tactic,
    load_records,
)
from phishdesk_analysis.sources import Register, sha256_of, write_index

WORK_COLUMNS = [
    "id",
    "file",
    "sha256",
    "from",
    "subject",
    "date",
    "is_phishing",
    "category",
    "tactics",
    "language",
    "label_confidence",
    "label_by",
    "reason",
]
LABEL_COLUMNS = [
    "id",
    "sha256",
    "is_phishing",
    "category",
    "tactics",
    "language",
    "label_confidence",
    "label_by",
    "group",
]
SPLITS = ("train", "dev", "test")


class CorpusError(ValueError):
    """Raised when labels, files or splits are inconsistent."""


# --- reading emails -------------------------------------------------------


def read_index(path: Path) -> dict[str, tuple[str, str]]:
    """index.csv -> {id: (relative file, sha256)}"""
    with open(path, newline="", encoding="utf-8") as f:
        return {row["id"]: (row["file"], row["sha256"]) for row in csv.DictReader(f)}


def parse_email(data: bytes) -> EmailMessage:
    msg = email.message_from_bytes(data, policy=policy.default)
    assert isinstance(msg, EmailMessage)
    return msg


def _header(msg: EmailMessage, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:  # malformed headers in old public mail
        return ""
    return " ".join(str(value).split()) if value is not None else ""


def sender_domain(msg: EmailMessage) -> str:
    address = parseaddr(_header(msg, "From"))[1]
    return address.rpartition("@")[2].lower().strip(".") or "unknown"


def sender_address(msg: EmailMessage) -> str:
    return parseaddr(_header(msg, "From"))[1].lower().strip() or "unknown"


def sender_group(msg: EmailMessage) -> str:
    """A grouping key that keeps one sender's emails together without naming them.

    Uses the full sender address, not the domain: in Enron almost every sender is
    on the same company domain, and phishing often spoofs the recipient's own
    domain, so domain grouping would lump unrelated emails into one huge group.
    Copies of the same campaign are still grouped by the near-duplicate check.
    """
    digest = hashlib.sha256(sender_address(msg).encode()).hexdigest()[:12]
    return f"sender-hash-{digest}"


def email_date(msg: EmailMessage) -> str | None:
    raw = _header(msg, "Date")
    try:
        return parsedate_to_datetime(raw).date().isoformat() if raw else None
    except (TypeError, ValueError, IndexError):
        return None


_TAGS = re.compile(r"(?is)<(style|script)[^>]*>.*?</\1>|<[^>]+>")


def plain_text(msg: EmailMessage) -> str:
    """Subject plus decoded text of all text parts, HTML tags removed."""
    parts = [_header(msg, "Subject")]
    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True)
            content = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""
        if part.get_content_subtype() == "html":
            content = html.unescape(_TAGS.sub(" ", content))
        parts.append(content)
    return " ".join(" ".join(parts).split())


# --- label sheets and export ---------------------------------------------


def make_label_sheet(
    index_path: Path,
    emails_dir: Path,
    out_csv: Path,
    prefill_is_phishing: str = "",
    sample: int | None = None,
    seed: int = 42,
    only_ids: set[str] | None = None,
) -> int:
    """Write a local work sheet. It contains real senders/subjects: never commit it."""
    index = read_index(index_path)
    ids = sorted(i for i in index if only_ids is None or i in only_ids)
    if sample is not None and sample < len(ids):
        ids = sorted(random.Random(seed).sample(ids, sample))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=WORK_COLUMNS)
        writer.writeheader()
        for msg_id in ids:
            rel, digest = index[msg_id]
            msg = parse_email((emails_dir / rel).read_bytes())
            writer.writerow(
                {
                    "id": msg_id,
                    "file": rel,
                    "sha256": digest,
                    "from": _header(msg, "From"),
                    "subject": _header(msg, "Subject"),
                    "date": email_date(msg) or "",
                    "is_phishing": prefill_is_phishing,
                    "category": "",
                    "tactics": "",
                    "language": "en",
                    "label_confidence": "",
                    "label_by": "",
                    "reason": "",
                }
            )
    return len(ids)


class LabelRow(BaseModel):
    """One committed label. Holds no sender, subject or text."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    is_phishing: bool
    category: Category
    tactics: list[Tactic] = Field(default_factory=list)
    language: str = Field(pattern=r"^[a-z]{2}$")
    label_confidence: Confidence
    label_by: str = Field(min_length=1)
    group: str = Field(pattern=r"^sender-hash-[0-9a-f]{12}$")


def _split_tactics(value: str) -> list[str]:
    return [t.strip() for t in re.split(r"[,;]", value) if t.strip()]


def _bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    raise CorpusError(f"is_phishing must be true/false, got '{value}'")


def export_labels(work_csvs: list[Path], index_path: Path, emails_dir: Path, out_csv: Path) -> int:
    """Validate labelled rows of one or more work sheets; write the safe labels file.

    Rows with an empty category are skipped (not labelled yet). Every exported row
    is checked against the local email's sha256 and the record consistency rules.
    """
    index = read_index(index_path)
    rows: list[LabelRow] = []
    for work_csv in work_csvs:
        rows += _read_work_sheet(work_csv, index, emails_dir)
    ids = [r.id for r in rows]
    if len(ids) != len(set(ids)):
        dupes = sorted(i for i, n in Counter(ids).items() if n > 1)
        raise CorpusError(f"ids labelled more than once: {dupes[:5]}")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LABEL_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for r in sorted(rows, key=lambda r: r.id):
            writer.writerow(
                {
                    "id": r.id,
                    "sha256": r.sha256,
                    "is_phishing": str(r.is_phishing).lower(),
                    "category": r.category.value,
                    "tactics": ",".join(t.value for t in r.tactics),
                    "language": r.language,
                    "label_confidence": r.label_confidence.value,
                    "label_by": r.label_by,
                    "group": r.group,
                }
            )
    return len(rows)


def _read_work_sheet(
    work_csv: Path, index: dict[str, tuple[str, str]], emails_dir: Path
) -> list[LabelRow]:
    rows: list[LabelRow] = []
    with open(work_csv, newline="", encoding="utf-8-sig") as f:
        for line_no, raw in enumerate(csv.DictReader(f), start=2):
            if not (raw.get("category") or "").strip():
                continue
            where = f"{work_csv.name}, row {line_no} ({raw.get('id')})"
            msg_id = raw["id"].strip()
            if msg_id not in index:
                raise CorpusError(f"{where}: id not in index.csv")
            rel, digest = index[msg_id]
            path = emails_dir / rel
            if sha256_of(path) != digest:
                raise CorpusError(f"{where}: local file does not match its sha256")
            try:
                row = LabelRow(
                    id=msg_id,
                    sha256=digest,
                    is_phishing=_bool(raw["is_phishing"]),
                    category=Category(raw["category"].strip()),
                    tactics=[Tactic(t) for t in _split_tactics(raw.get("tactics", ""))],
                    language=(raw.get("language") or "en").strip(),
                    label_confidence=Confidence(raw["label_confidence"].strip()),
                    label_by=raw["label_by"].strip(),
                    group=sender_group(parse_email(path.read_bytes())),
                )
            except (ValueError, ValidationError) as exc:
                raise CorpusError(f"{where}: {exc}") from exc
            if row.is_phishing != (row.category in PHISHING_CATEGORIES):
                raise CorpusError(f"{where}: is_phishing does not match category")
            rows.append(row)
    return rows


def load_labels(path: Path) -> list[LabelRow]:
    with open(path, newline="", encoding="utf-8") as f:
        return [
            LabelRow(
                id=r["id"],
                sha256=r["sha256"],
                is_phishing=_bool(r["is_phishing"]),
                category=Category(r["category"]),
                tactics=[Tactic(t) for t in _split_tactics(r["tactics"])],
                language=r["language"],
                label_confidence=Confidence(r["label_confidence"]),
                label_by=r["label_by"],
                group=r["group"],
            )
            for r in csv.DictReader(f)
        ]


# --- building records -----------------------------------------------------


def build_records(
    register: Register, raw_root: Path, labels_dir: Path, synthetic_jsonl: Path, repo_root: Path
) -> tuple[list[EmailRecord], dict[str, Path]]:
    """Join committed labels with verified local emails, plus synthetic records.

    Returns the records and {record id: path of its .eml} for text-based checks.
    """
    records: list[EmailRecord] = []
    paths: dict[str, Path] = {}
    for labels_file in sorted(labels_dir.glob("*.csv")):
        source = register.get(labels_file.stem)
        if source.status not in {"approved", "approved-local"}:
            raise CorpusError(f"labels for '{source.id}' but its status is '{source.status}'")
        src_dir = raw_root / source.id
        index = read_index(src_dir / "index.csv")
        for label in load_labels(labels_file):
            if label.id not in index:
                raise CorpusError(f"{labels_file.name}: {label.id} missing from local index")
            path = src_dir / "emails" / index[label.id][0]
            if not path.exists() or sha256_of(path) != label.sha256:
                raise CorpusError(f"{label.id}: local email missing or changed (sha256 mismatch)")
            msg = parse_email(path.read_bytes())
            records.append(
                EmailRecord(
                    id=label.id,
                    source=source.id,
                    source_ref=f"{source.name}: {index[label.id][0]}",
                    licence=source.licence,
                    redistributable=source.redistributable,
                    language=label.language,
                    date=email_date(msg),
                    template_family=label.group,
                    is_phishing=label.is_phishing,
                    category=label.category,
                    tactics=label.tactics,
                    label_by=label.label_by,
                    label_confidence=label.label_confidence,
                    raw_path=path.relative_to(repo_root).as_posix(),
                )
            )
            paths[label.id] = path
    if not synthetic_jsonl.exists():
        raise CorpusError(f"{synthetic_jsonl} not found: run scripts/generate_synthetic.py first")
    for record in load_records(synthetic_jsonl):
        records.append(record)
        paths[record.id] = repo_root / record.raw_path
    ids = [r.id for r in records]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    if dupes:
        raise CorpusError(f"duplicate record ids: {dupes[:5]}")
    return records, paths


# --- deduplication --------------------------------------------------------


def normalise(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def shingles(text: str, size: int = 3) -> set[str]:
    words = text.split()
    if len(words) < size:
        return {" ".join(words)}
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}


class DedupResult(BaseModel):
    kept: list[str]
    dropped: dict[str, str]  # dropped id -> kept id it duplicates
    groups: dict[str, str]  # kept id -> final group


def dedupe(
    records: list[EmailRecord], texts: dict[str, str], near_threshold: float = 0.9
) -> DedupResult:
    """Drop exact duplicates; merge near-duplicates and same-family records into one group."""
    by_hash: dict[str, str] = {}
    dropped: dict[str, str] = {}
    kept: list[EmailRecord] = []
    for r in sorted(records, key=lambda r: r.id):
        key = hashlib.sha256(normalise(texts[r.id]).encode()).hexdigest()
        if key in by_hash:
            dropped[r.id] = by_hash[key]
        else:
            by_hash[key] = r.id
            kept.append(r)

    parent = {r.id: r.id for r in kept}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    first_in_family: dict[str, str] = {}
    for r in kept:
        if r.template_family in first_in_family:
            union(r.id, first_in_family[r.template_family])
        else:
            first_in_family[r.template_family] = r.id
    sigs = {r.id: shingles(normalise(texts[r.id])) for r in kept}
    ordered = [r.id for r in kept]
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            if find(a) == find(b):
                continue
            sa, sb = sigs[a], sigs[b]
            if len(sa & sb) / max(1, len(sa | sb)) >= near_threshold:
                union(a, b)
    return DedupResult(kept=ordered, dropped=dropped, groups={i: find(i) for i in ordered})


# --- splitting ------------------------------------------------------------


def split_records(
    records: list[EmailRecord],
    groups: dict[str, str],
    ratios: tuple[float, float, float] = (0.7, 0.15, 0.15),
    seed: int = 42,
    synthetic_to_train: bool = True,
) -> dict[str, list[str]]:
    """Group-aware split, balanced per category. A group never spans two splits.

    With synthetic_to_train (the default), synthetic records only augment train and
    the ratios apply to real emails, so dev and test contain real mail only.
    Groups are placed largest-first (ties in seeded random order) into the split
    furthest below its target share for that group's main category.
    """
    by_id = {r.id: r for r in records if r.id in groups}
    result: dict[str, list[str]] = {name: [] for name in SPLITS}
    members: dict[str, list[str]] = defaultdict(list)
    for rid, group in groups.items():
        if synthetic_to_train and by_id[rid].source == "synthetic":
            result["train"].append(rid)
        else:
            members[group].append(rid)
    totals = Counter(by_id[i].category for ids in members.values() for i in ids)
    assigned: dict[Category, Counter[str]] = defaultdict(Counter)
    rng = random.Random(seed)
    group_ids = sorted(members)
    rng.shuffle(group_ids)
    group_ids.sort(key=lambda g: len(members[g]), reverse=True)

    for group in group_ids:
        cats = Counter(by_id[i].category for i in members[group])
        main = cats.most_common(1)[0][0]
        deficits = [
            ratios[k] * totals[main] - assigned[main][name] for k, name in enumerate(SPLITS)
        ]
        target = SPLITS[max(range(3), key=lambda k: (deficits[k], -k))]
        for rid in members[group]:
            result[target].append(rid)
            assigned[by_id[rid].category][target] += 1
    return {name: sorted(ids) for name, ids in result.items()}


def write_splits(splits: dict[str, list[str]], dedup: DedupResult, out: Path, seed: int) -> None:
    payload = {
        "version": 1,
        "seed": seed,
        "ratios": [0.7, 0.15, 0.15],
        "rule": "ratios apply to real emails; synthetic records are train-only",
        "counts": {name: len(ids) for name, ids in splits.items()},
        "dropped_duplicates": dict(sorted(dedup.dropped.items())),
        **splits,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


# --- agreement ------------------------------------------------------------


def label_agreement(a: dict[str, dict[str, str]], b: dict[str, dict[str, str]]) -> dict[str, float]:
    """Agreement on shared ids: per field, full match and Cohen's kappa for category."""
    shared = sorted(set(a) & set(b))
    if not shared:
        raise CorpusError("no shared labelled ids to compare")

    def tactics(row: dict[str, str]) -> frozenset[str]:
        return frozenset(_split_tactics(row.get("tactics", "")))

    n = len(shared)
    phish = sum(a[i]["is_phishing"].lower() == b[i]["is_phishing"].lower() for i in shared)
    cat = sum(a[i]["category"] == b[i]["category"] for i in shared)
    tac = sum(tactics(a[i]) == tactics(b[i]) for i in shared)
    full = sum(
        a[i]["is_phishing"].lower() == b[i]["is_phishing"].lower()
        and a[i]["category"] == b[i]["category"]
        for i in shared
    )
    ca, cb = Counter(a[i]["category"] for i in shared), Counter(b[i]["category"] for i in shared)
    p_o = cat / n
    p_e = sum(ca[c] * cb[c] for c in set(ca) | set(cb)) / (n * n)
    kappa = 1.0 if p_e == 1 else (p_o - p_e) / (1 - p_e)
    return {
        "shared": n,
        "is_phishing": phish / n,
        "category": cat / n,
        "tactics": tac / n,
        "full_match": full / n,
        "category_kappa": kappa,
    }


def review_sample(labels_dir: Path, fraction: float, seed: int) -> dict[str, list[str]]:
    """Seeded random sample of committed real labels, per source, for double-labelling.

    Uses the committed labels files, so anyone with the same branch gets the same ids.
    """
    sample: dict[str, list[str]] = {}
    for path in sorted(labels_dir.glob("*.csv")):
        ids = sorted(r.id for r in load_labels(path))
        if not ids:
            continue
        count = max(1, round(len(ids) * fraction))
        sample[path.stem] = sorted(random.Random(f"{seed}:{path.stem}").sample(ids, count))
    return sample


def disagreements(
    a: dict[str, dict[str, str]], b: dict[str, dict[str, str]]
) -> list[tuple[str, str, str]]:
    """(id, label in a, label in b) for shared ids whose category or tactics differ."""

    def show(row: dict[str, str]) -> str:
        tactics = ",".join(sorted(_split_tactics(row.get("tactics", ""))))
        return f"{row['category']} [{tactics}]"

    out = []
    for i in sorted(set(a) & set(b)):
        if show(a[i]) != show(b[i]):
            out.append((i, show(a[i]), show(b[i])))
    return out


# --- Enron candidate selection -------------------------------------------

URGENT_WORDS = (
    "urgent",
    "asap",
    "deadline",
    "due today",
    "due by",
    "action required",
    "expires",
    "expire",
    "end of day",
    "reminder",
    "immediately",
    "password",
    "invoice",
    "payment due",
)


def select_enron(
    tar_path: Path, out_dir: Path, urgent: int, other: int, seed: int = 42
) -> list[tuple[str, str, str]]:
    """Stream the Enron archive once and sample inbox emails into two buckets.

    'urgent' holds messages containing time-pressure words (legit_urgent candidates),
    'other' holds the rest (benign candidates). Reservoir sampling with a fixed seed
    gives the same selection for the same archive. Returns index rows.
    """
    rng = random.Random(seed)
    buckets: dict[str, list[tuple[str, bytes]]] = {"urgent": [], "other": []}
    sizes = {"urgent": urgent, "other": other}
    seen = Counter[str]()
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or "/inbox/" not in member.name:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            data = handle.read()
            text = data[:20000].decode("latin-1").lower()
            bucket = "urgent" if any(w in text for w in URGENT_WORDS) else "other"
            seen[bucket] += 1
            if len(buckets[bucket]) < sizes[bucket]:
                buckets[bucket].append((member.name, data))
            else:
                j = rng.randrange(seen[bucket])
                if j < sizes[bucket]:
                    buckets[bucket][j] = (member.name, data)
    emails_dir = out_dir / "emails"
    emails_dir.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, str]] = []
    for items in buckets.values():
        for name, data in items:
            msg_id = f"enron-{hashlib.sha256(name.encode()).hexdigest()[:10]}"
            filename = f"{msg_id}.eml"
            (emails_dir / filename).write_bytes(data)
            rows.append((msg_id, filename, hashlib.sha256(data).hexdigest()))
    rows.sort()
    write_index(rows, out_dir / "index.csv")
    (out_dir / "candidates.json").write_text(
        json.dumps(
            {
                b: sorted(f"enron-{hashlib.sha256(n.encode()).hexdigest()[:10]}" for n, _ in items)
                for b, items in buckets.items()
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return rows
