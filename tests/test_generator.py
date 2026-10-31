"""Tests for the synthetic generator: determinism, safety, held-back families, validity."""

import email
import json
from collections import Counter
from email import policy
from pathlib import Path

import pytest

from phishdesk_analysis.generator import (
    SYNTHETIC_HEADER,
    GeneratorError,
    generate_email,
    load_config,
    placeholders,
    plan_by_category,
    plan_per_family,
    write_dataset,
)
from phishdesk_analysis.records import PHISHING_CATEGORIES, Category, EmailRecord, load_records
from phishdesk_analysis.safety import real_brands_in, unreserved_domains

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "data" / "generator"
CONFIG = load_config(CONFIG_DIR)
SEEDS = range(6)
ALL_EMAILS = [(f, s, *generate_email(CONFIG, f, s)) for f in CONFIG.families for s in SEEDS]


def readable_text(data: bytes) -> str:
    """Headers plus decoded body parts, so encodings can't hide a domain or brand."""
    msg = email.message_from_bytes(data, policy=policy.default)
    parts = [f"{k}: {v}" for k, v in msg.items()]
    for part in msg.walk():
        if part.is_multipart():
            continue
        content = part.get_content()
        parts.append(content if isinstance(content, str) else content.decode("utf-8", "replace"))
    return "\n".join(parts)


def ids(item):
    return f"{item[0].id}-{item[1]}"


# --- configuration --------------------------------------------------------


def test_every_category_has_two_active_and_one_held_back_family():
    active = Counter(f.category for f in CONFIG.families if not f.held_back)
    held = Counter(f.category for f in CONFIG.families if f.held_back)
    for category in Category:
        assert active[category] >= 2, category
        assert held[category] >= 1, category


def test_templates_only_use_known_slots():
    data, _ = generate_email(CONFIG, CONFIG.families[0], 0)
    assert data  # rendering itself raises on unknown slots; this checks all families below
    for family in CONFIG.families:
        for text in family.subjects + family.bodies:
            assert "{" not in text.format(**dict.fromkeys(placeholders(text), "x"))


def test_config_files_contain_no_real_domains_or_brands():
    for path in CONFIG_DIR.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert unreserved_domains(text) == [], path.name
        assert real_brands_in(text) == [], path.name


def test_brand_domains_are_reserved():
    domains = [b.domain for b in CONFIG.brands.brands] + [CONFIG.brands.organisation.domain]
    domains += CONFIG.brands.unknown_sender_domains
    domains += [p.format(slug="x") for p in CONFIG.brands.lure_domain_patterns]
    assert unreserved_domains(" ".join(f"https://{d}" for d in domains)) == []


# --- determinism ----------------------------------------------------------


def test_same_family_and_seed_give_identical_bytes():
    family = CONFIG.families[0]
    assert generate_email(CONFIG, family, 3)[0] == generate_email(CONFIG, family, 3)[0]


def test_different_seeds_give_different_emails():
    family = CONFIG.families[0]
    assert generate_email(CONFIG, family, 1)[0] != generate_email(CONFIG, family, 2)[0]


def test_written_dataset_is_reproducible(tmp_path):
    plan = plan_per_family(CONFIG, 2)
    write_dataset(CONFIG, plan, tmp_path / "a", tmp_path / "a.jsonl")
    write_dataset(CONFIG, plan, tmp_path / "b", tmp_path / "b.jsonl")
    assert (tmp_path / "a.jsonl").read_bytes() == (tmp_path / "b.jsonl").read_bytes()
    for eml in (tmp_path / "a").glob("*.eml"):
        assert eml.read_bytes() == (tmp_path / "b" / eml.name).read_bytes()


# --- safety ---------------------------------------------------------------


@pytest.mark.parametrize("item", ALL_EMAILS, ids=ids)
def test_generated_email_uses_only_reserved_domains(item):
    _, _, data, _ = item
    assert unreserved_domains(readable_text(data)) == []


@pytest.mark.parametrize("item", ALL_EMAILS, ids=ids)
def test_generated_email_contains_no_real_brands(item):
    _, _, data, _ = item
    assert real_brands_in(readable_text(data)) == []


@pytest.mark.parametrize("item", ALL_EMAILS, ids=ids)
def test_generated_email_is_marked_synthetic_and_parses(item):
    family, seed, data, record = item
    msg = email.message_from_bytes(data, policy=policy.default)
    assert str(msg[SYNTHETIC_HEADER]).strip().startswith("true;")
    assert msg["Message-ID"] == f"<{record.id}@generator.phishdesk.test>"
    body = msg.get_body(preferencelist=("plain",))
    assert body is not None and body.get_content().strip()


def test_attachments_are_inert():
    for family, _, data, _ in ALL_EMAILS:
        msg = email.message_from_bytes(data, policy=policy.default)
        for part in msg.iter_attachments():
            content = part.get_content()
            text = content if isinstance(content, str) else content.decode()
            assert "<script" not in text.lower() and "http" not in text.lower(), family.id


# --- records --------------------------------------------------------------


@pytest.mark.parametrize("item", ALL_EMAILS, ids=ids)
def test_records_are_valid_and_match_family(item):
    family, seed, _, record = item
    EmailRecord.model_validate(record.model_dump())
    assert record.category == family.category
    assert record.is_phishing == (family.category in PHISHING_CATEGORIES)
    assert record.template_family == family.id
    assert f"seed {seed}" in record.source_ref


def test_written_records_load_without_errors(tmp_path):
    write_dataset(CONFIG, plan_per_family(CONFIG, 3), tmp_path / "eml", tmp_path / "r.jsonl")
    records = load_records(tmp_path / "r.jsonl")
    assert len(records) == len(list((tmp_path / "eml").glob("*.eml")))
    assert all(r.source == "synthetic" for r in records)


# --- held-back families and planning -------------------------------------


def test_held_back_families_are_skipped_by_default():
    planned = {f.id for f, _ in plan_per_family(CONFIG, 1)}
    held = {f.id for f in CONFIG.families if f.held_back}
    assert planned.isdisjoint(held)


def test_held_back_families_only_with_explicit_flag():
    planned = {f.id for f, _ in plan_per_family(CONFIG, 1, include_held_back=True)}
    assert {f.id for f in CONFIG.families} == planned


def test_plan_by_category_hits_exact_counts():
    counts = {Category.CREDENTIAL: 7, Category.BENIGN: 4}
    plan = plan_by_category(CONFIG, counts)
    got = Counter(f.category for f, _ in plan)
    assert got == Counter(counts)
    assert len({(f.id, s) for f, s in plan}) == len(plan)


def test_unknown_family_is_rejected():
    with pytest.raises(GeneratorError):
        CONFIG.family("does-not-exist")


def test_family_with_unknown_slot_is_rejected(tmp_path):
    for name in ("brands.json", "families.json"):
        (tmp_path / name).write_text((CONFIG_DIR / name).read_text("utf-8"), "utf-8")
    data = json.loads((tmp_path / "families.json").read_text("utf-8"))
    data["families"][0]["bodies"] = ["Hello {not_a_slot}"]
    (tmp_path / "families.json").write_text(json.dumps(data), "utf-8")
    config = load_config(tmp_path)
    with pytest.raises(GeneratorError, match="unknown slots"):
        generate_email(config, config.families[0], 0)
