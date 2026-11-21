"""Tests for labelling, label export, corpus building, dedup, splits and agreement.

All emails here are synthetic and built in temporary folders.
"""

import csv
import io
import json
import shutil
import tarfile
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishdesk_analysis.corpus import (
    CorpusError,
    build_records,
    dedupe,
    export_labels,
    label_agreement,
    load_labels,
    make_label_sheet,
    parse_email,
    plain_text,
    select_enron,
    split_records,
)
from phishdesk_analysis.generator import load_config, plan_per_family, write_dataset
from phishdesk_analysis.records import Category
from phishdesk_analysis.safety import unreserved_domains
from phishdesk_analysis.sources import Register, load_register, sha256_of, write_index

ROOT = Path(__file__).resolve().parents[1]


def make_eml(i: int, subject: str, body: str, domain: str = "mailnotice.test") -> bytes:
    msg = EmailMessage()
    msg["From"] = f"Sender {i} <sender{i}@{domain}>"
    msg["To"] = "user@hollowmere.example"
    msg["Subject"] = subject
    msg["Date"] = "Mon, 06 Jan 2025 04:26:00 +0000"
    msg.set_content(body)
    return msg.as_bytes()


@pytest.fixture
def env(tmp_path):
    """A fake approved 'nazario' source with 6 synthetic emails, plus synthetic records."""
    raw = tmp_path / "data" / "raw" / "public"
    src = raw / "nazario"
    (src / "emails").mkdir(parents=True)
    rows = []
    for i in range(6):
        data = make_eml(
            i,
            f"Verify mailbox {i}",
            f"Unique body number {i} " * (i + 3),
            domain=f"lure{i % 3}.test",
        )
        name = f"nazario-2099-{i:04d}.eml"
        (src / "emails" / name).write_bytes(data)
        rows.append((f"nazario-2099-{i:04d}", name, sha256_of(src / "emails" / name)))
    write_index(rows, src / "index.csv")

    register_data = json.loads((ROOT / "data" / "sources.json").read_text("utf-8"))
    for s in register_data["sources"]:
        if s["id"] == "nazario":
            s["status"] = "approved"
    register = Register.model_validate(register_data)

    config = load_config(ROOT / "data" / "generator")
    synthetic = tmp_path / "data" / "processed" / "synthetic.jsonl"
    write_dataset(
        config, plan_per_family(config, 2), tmp_path / "data" / "raw" / "synthetic", synthetic
    )
    return {
        "root": tmp_path,
        "raw": raw,
        "src": src,
        "register": register,
        "synthetic": synthetic,
        "labels": tmp_path / "data" / "labels",
        "work": tmp_path / "work",
    }


def label_sheet(env, edits: dict[int, dict[str, str]]) -> Path:
    sheet = env["work"] / "nazario.csv"
    make_label_sheet(env["src"] / "index.csv", env["src"] / "emails", sheet, "true")
    with open(sheet, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        fields = list(rows[0].keys())
    for i, change in edits.items():
        rows[i].update(change)
    with open(sheet, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return sheet


GOOD = {
    "category": "credential",
    "tactics": "urgency, impersonation",
    "label_confidence": "high",
    "label_by": "person2",
}


# --- label sheets and export ---------------------------------------------


def test_label_sheet_has_readable_columns_and_prefill(env):
    sheet = label_sheet(env, {})
    rows = list(csv.DictReader(open(sheet, encoding="utf-8")))
    assert len(rows) == 6
    assert rows[0]["subject"] == "Verify mailbox 0" and rows[0]["is_phishing"] == "true"


def test_label_sheet_sample_is_deterministic(env):
    a, b = env["work"] / "a.csv", env["work"] / "b.csv"
    make_label_sheet(env["src"] / "index.csv", env["src"] / "emails", a, sample=3, seed=7)
    make_label_sheet(env["src"] / "index.csv", env["src"] / "emails", b, sample=3, seed=7)
    assert a.read_bytes() == b.read_bytes()


def test_export_keeps_only_labelled_rows_and_safe_columns(env):
    sheet = label_sheet(env, {0: GOOD, 2: GOOD})
    out = env["labels"] / "nazario.csv"
    assert export_labels([sheet], env["src"] / "index.csv", env["src"] / "emails", out) == 2
    text = out.read_text("utf-8")
    assert "Verify mailbox" not in text and "sender0" not in text
    assert unreserved_domains(text) == [] and ".test" not in text
    labels = load_labels(out)
    assert [r.id for r in labels] == ["nazario-2099-0000", "nazario-2099-0002"]
    assert labels[0].group.startswith("sender-hash-")


def test_groups_follow_sender_address_not_domain():
    from phishdesk_analysis.corpus import sender_group

    def msg(sender):
        return parse_email(make_eml(0, "s", "b").replace(b"sender0@mailnotice.test", sender))

    same = sender_group(msg(b"alice@corp.test"))
    assert same == sender_group(msg(b"ALICE@corp.test"))
    assert same != sender_group(msg(b"bob@corp.test"))  # same domain, different sender


@pytest.mark.parametrize(
    "change, message",
    [
        ({"category": "benign"}, "does not match"),
        ({"category": "phishy"}, "phishy"),
        ({"tactics": "fear"}, "fear"),
        ({"label_confidence": ""}, "row 2"),
        ({"is_phishing": "maybe"}, "true/false"),
    ],
)
def test_export_rejects_bad_labels(env, change, message):
    sheet = label_sheet(env, {0: GOOD | change})
    with pytest.raises(CorpusError, match=message):
        export_labels(
            [sheet], env["src"] / "index.csv", env["src"] / "emails", env["labels"] / "nazario.csv"
        )


def test_export_rejects_changed_email(env):
    sheet = label_sheet(env, {0: GOOD})
    (env["src"] / "emails" / "nazario-2099-0000.eml").write_bytes(b"tampered")
    with pytest.raises(CorpusError, match="sha256"):
        export_labels(
            [sheet], env["src"] / "index.csv", env["src"] / "emails", env["labels"] / "nazario.csv"
        )


def test_export_rejects_id_labelled_twice(env):
    sheet = label_sheet(env, {0: GOOD})
    copy = env["work"] / "nazario-copy.csv"
    shutil.copy(sheet, copy)
    with pytest.raises(CorpusError, match="more than once"):
        export_labels(
            [sheet, copy],
            env["src"] / "index.csv",
            env["src"] / "emails",
            env["labels"] / "nazario.csv",
        )


# --- building records -----------------------------------------------------


def export_all(env):
    sheet = label_sheet(env, {i: GOOD for i in range(6)})
    export_labels(
        [sheet], env["src"] / "index.csv", env["src"] / "emails", env["labels"] / "nazario.csv"
    )


def test_build_joins_labels_and_synthetic(env):
    export_all(env)
    records, paths = build_records(
        env["register"], env["raw"], env["labels"], env["synthetic"], env["root"]
    )
    sources = Counter(r.source for r in records)
    assert sources["nazario"] == 6 and sources["synthetic"] > 0
    assert all(p.exists() for p in paths.values())
    nazario = next(r for r in records if r.source == "nazario")
    assert nazario.licence == "CC-BY-4.0" and str(nazario.date) == "2025-01-06"


def test_build_fails_when_local_email_changed(env):
    export_all(env)
    (env["src"] / "emails" / "nazario-2099-0001.eml").write_bytes(b"changed")
    with pytest.raises(CorpusError, match="sha256"):
        build_records(env["register"], env["raw"], env["labels"], env["synthetic"], env["root"])


def test_build_refuses_labels_for_pending_source(env):
    export_all(env)
    for s in env["register"].sources:
        if s.id == "nazario":
            s.status = "pending"
    with pytest.raises(CorpusError, match="status"):
        build_records(env["register"], env["raw"], env["labels"], env["synthetic"], env["root"])


def test_build_requires_synthetic_records(env):
    export_all(env)
    env["synthetic"].unlink()
    with pytest.raises(CorpusError, match="generate_synthetic"):
        build_records(env["register"], env["raw"], env["labels"], env["synthetic"], env["root"])


# --- dedup and splits -----------------------------------------------------


def built(env):
    export_all(env)
    records, paths = build_records(
        env["register"], env["raw"], env["labels"], env["synthetic"], env["root"]
    )
    texts = {i: plain_text(parse_email(p.read_bytes())) for i, p in paths.items()}
    return records, texts


def test_exact_duplicates_are_dropped(env):
    records, texts = built(env)
    a, b = records[0].id, records[1].id
    texts[b] = texts[a]
    result = dedupe(records, texts)
    assert max(a, b) in result.dropped and min(a, b) in result.kept


def test_near_duplicates_share_a_group(env):
    records, texts = built(env)
    nazario = sorted(r.id for r in records if r.source == "nazario")
    words = " ".join(f"word{i}" for i in range(200))
    texts[nazario[0]], texts[nazario[1]] = words, words + " extra"
    result = dedupe(records, texts)
    assert result.groups[nazario[0]] == result.groups[nazario[1]]


def test_same_family_records_share_a_group(env):
    records, texts = built(env)
    result = dedupe(records, texts)
    fam = [r.id for r in records if r.template_family == "cred-mailbox-full"]
    assert len({result.groups[i] for i in fam}) == 1


def test_split_keeps_groups_together_and_is_deterministic(env):
    records, texts = built(env)
    result = dedupe(records, texts)
    kept = [r for r in records if r.id in result.groups]
    first = split_records(kept, result.groups, seed=1)
    assert first == split_records(kept, result.groups, seed=1)
    where = {rid: name for name, ids in first.items() for rid in ids}
    assert set(where) == set(result.groups)
    for group in set(result.groups.values()):
        assert len({where[i] for i, g in result.groups.items() if g == group}) == 1


def test_split_spreads_each_category_when_groups_allow():
    from phishdesk_analysis.records import EmailRecord

    records, groups = [], {}
    for cat, phish in ((Category.BENIGN, False), (Category.CREDENTIAL, True)):
        for i in range(40):
            rid = f"r-{cat.value}-{i:03d}"
            records.append(
                EmailRecord(
                    id=rid.replace("_", "-"),
                    source="nazario",
                    source_ref="t",
                    licence="t",
                    redistributable=True,
                    language="en",
                    template_family=f"g{i}",
                    is_phishing=phish,
                    category=cat,
                    label_by="t",
                    label_confidence="high",
                    raw_path="x",
                )
            )
            groups[rid.replace("_", "-")] = f"{cat.value}-g{i}"
    splits = split_records(records, groups, seed=3)
    counts = {
        name: Counter(r.category for r in records if r.id in set(ids))
        for name, ids in splits.items()
    }
    for cat in (Category.BENIGN, Category.CREDENTIAL):
        assert counts["train"][cat] == 28 and counts["dev"][cat] == 6 and counts["test"][cat] == 6


def test_synthetic_records_are_train_only_and_real_ones_are_spread(env):
    records, texts = built(env)
    result = dedupe(records, texts)
    kept = [r for r in records if r.id in result.groups]
    splits = split_records(kept, result.groups, seed=1)
    source = {r.id: r.source for r in kept}
    assert all(source[i] != "synthetic" for name in ("dev", "test") for i in splits[name])
    assert any(source[i] == "synthetic" for i in splits["train"])
    real_splits = {name for name, ids in splits.items() for i in ids if source[i] == "nazario"}
    assert len(real_splits) >= 2  # 6 real emails, each its own sender, get spread out


# --- agreement ------------------------------------------------------------


def test_agreement_scores():
    a = {
        "1": {"is_phishing": "true", "category": "credential", "tactics": "urgency"},
        "2": {"is_phishing": "false", "category": "benign", "tactics": ""},
        "3": {"is_phishing": "true", "category": "payment", "tactics": "impersonation"},
    }
    b = {
        "1": {"is_phishing": "true", "category": "credential", "tactics": "urgency"},
        "2": {"is_phishing": "false", "category": "benign", "tactics": ""},
        "3": {"is_phishing": "true", "category": "credential", "tactics": "impersonation"},
    }
    result = label_agreement(a, b)
    assert result["shared"] == 3 and result["category"] == pytest.approx(2 / 3)
    assert result["tactics"] == 1.0 and result["full_match"] == pytest.approx(2 / 3)
    assert label_agreement(a, a)["category_kappa"] == 1.0


def test_agreement_needs_shared_ids():
    with pytest.raises(CorpusError):
        label_agreement({"1": {}}, {"2": {}})


# --- Enron selection ------------------------------------------------------


def test_select_enron_samples_inbox_only_and_is_deterministic(tmp_path):
    tar_path = tmp_path / "enron.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        for i in range(30):
            folder = "inbox" if i % 3 else "sent"
            body = f"Please reply by the deadline {i}" if i % 2 else f"Lunch notes {i}"
            data = make_eml(i, f"Msg {i}", body, "hollowmere.example")
            info = tarfile.TarInfo(f"maildir/user{i % 4}/{folder}/{i}.")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    rows_a = select_enron(tar_path, tmp_path / "a", urgent=4, other=3, seed=5)
    rows_b = select_enron(tar_path, tmp_path / "b", urgent=4, other=3, seed=5)
    assert rows_a == rows_b and len(rows_a) == 7
    candidates = json.loads((tmp_path / "a" / "candidates.json").read_text("utf-8"))
    assert len(candidates["urgent"]) == 4 and len(candidates["other"]) == 3
    for _, name, _ in rows_a:
        assert b"Msg" in (tmp_path / "a" / "emails" / name).read_bytes()


def test_real_register_is_loadable():
    assert load_register(ROOT / "data" / "sources.json").get("nazario")
