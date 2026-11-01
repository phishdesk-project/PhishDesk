"""Deterministic synthetic email generator.

Every email uses invented brands from data/generator/brands.json and only
reserved test domains. The same family, generator version and seed always
produce byte-identical output. Held-back families are reserved for the
Month 7 fresh test set and are skipped unless explicitly requested.
"""

from __future__ import annotations

import datetime as dt
import json
import random
import string
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import format_datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from phishdesk_analysis.records import PHISHING_CATEGORIES, Category, EmailRecord, Tactic

GENERATOR_VERSION = "0.1"
SYNTHETIC_HEADER = "X-PhishDesk-Synthetic"
ATTACHMENT_BODY = (
    b"<!-- PhishDesk synthetic test attachment. No scripts, links or active content. -->\n"
    b"<p>Synthetic attachment used for testing only.</p>\n"
)

SenderMode = Literal[
    "lure", "fake_it", "spoofed_manager", "unknown", "colleague", "brand", "org_it", "org_hr"
]


class GeneratorError(ValueError):
    """Raised for invalid generator configuration or requests."""


class Organisation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    domain: str
    it_desk: str
    hr_team: str


class Brand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    domain: str
    kind: str


class BrandConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organisation: Organisation
    brands: list[Brand]
    lure_domain_patterns: list[str] = Field(min_length=1)
    unknown_sender_domains: list[str] = Field(min_length=1)
    first_names: list[str] = Field(min_length=2)
    last_names: list[str] = Field(min_length=2)


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str
    subtype: Literal["html", "plain"]


class Family(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    category: Category
    held_back: bool
    brand_kind: str | None
    sender: SenderMode
    reply_to: Literal["none", "lure", "freemail"]
    link_path: str | None
    attachment: Attachment | None
    tactics: list[Tactic]
    subjects: list[str] = Field(min_length=1)
    bodies: list[str] = Field(min_length=1)


class FamilyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    families: list[Family]


class GeneratorConfig(BaseModel):
    brands: BrandConfig
    families: list[Family]

    def family(self, family_id: str) -> Family:
        for family in self.families:
            if family.id == family_id:
                return family
        raise GeneratorError(f"unknown family '{family_id}'")


def load_config(config_dir: str | Path) -> GeneratorConfig:
    config_dir = Path(config_dir)
    brands = BrandConfig.model_validate_json((config_dir / "brands.json").read_text("utf-8"))
    families = FamilyFile.model_validate_json((config_dir / "families.json").read_text("utf-8"))
    ids = [f.id for f in families.families]
    if len(ids) != len(set(ids)):
        raise GeneratorError("duplicate family ids in families.json")
    kinds = {b.kind for b in brands.brands}
    for f in families.families:
        if f.brand_kind is not None and f.brand_kind not in kinds:
            raise GeneratorError(f"family '{f.id}' needs brand kind '{f.brand_kind}'")
    return GeneratorConfig(brands=brands, families=families.families)


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def _render(text: str, slots: dict[str, str], family_id: str) -> str:
    missing = placeholders(text) - slots.keys()
    if missing:
        raise GeneratorError(f"family '{family_id}' uses unknown slots: {sorted(missing)}")
    return text.format(**slots)


def generate_email(config: GeneratorConfig, family: Family, seed: int) -> tuple[bytes, EmailRecord]:
    """Build one email and its record. Deterministic for (family, version, seed)."""
    rng = random.Random(f"{GENERATOR_VERSION}:{family.id}:{seed}")
    cfg = config.brands
    org = cfg.organisation
    record_id = f"syn-{family.id}-{seed:04d}"

    brand = None
    if family.brand_kind is not None:
        brand = rng.choice([b for b in cfg.brands if b.kind == family.brand_kind])
    lure_slug = brand.slug if brand else org.slug
    if family.sender == "unknown":
        lure_domain = rng.choice(cfg.unknown_sender_domains)
    else:
        lure_domain = rng.choice(cfg.lure_domain_patterns).format(slug=lure_slug)
    freemail = rng.choice(cfg.unknown_sender_domains)

    recipient_first, recipient_last = rng.choice(cfg.first_names), rng.choice(cfg.last_names)
    sender_first, sender_last = rng.choice(cfg.first_names), rng.choice(cfg.last_names)
    when = dt.datetime(2026, 1, 5, tzinfo=dt.UTC) + dt.timedelta(
        days=rng.randrange(300), hours=rng.randrange(7, 18), minutes=rng.randrange(60)
    )

    is_phishing = family.category in PHISHING_CATEGORIES
    link = ""
    if family.link_path:
        token = "".join(rng.choices(string.ascii_lowercase + string.digits, k=10))
        if is_phishing:
            link = f"https://{lure_domain}/{family.link_path}?id={token}"
        elif brand:
            link = f"https://portal.{brand.domain}/{family.link_path}"
        else:
            link = f"https://intranet.{org.domain}/{family.link_path}"

    slots = {
        "recipient_first": recipient_first,
        "recipient_last": recipient_last,
        "sender_first": sender_first,
        "sender_last": sender_last,
        "brand": brand.name if brand else org.name,
        "org": org.name,
        "it_desk": org.it_desk,
        "hr_team": org.hr_team,
        "link": link,
        "percent": str(rng.randint(95, 99)),
        "deadline": rng.choice(["within 24 hours", "by end of day", "within 2 hours", "today"]),
        "doc_name": rng.choice(["Q3 contract.pdf", "Salary review.xlsx", "Project budget.docx"]),
        "invoice_no": str(rng.randint(10000, 99999)),
        "amount": f"£{rng.randint(250, 9800):,}.{rng.randint(0, 99):02d}",
        "account_no": f"{rng.randint(0, 99999999):08d}",
        "sort_code": f"{rng.randint(0, 99):02d}-{rng.randint(0, 99):02d}-{rng.randint(0, 99):02d}",
        "gift_count": str(rng.randint(3, 8)),
        "gift_value": f"£{rng.choice([50, 100, 200])}",
        "tracking_no": f"SW{rng.randint(10**8, 10**9 - 1)}",
        "ref_no": f"N-{rng.randint(1000, 9999)}",
        "file_count": str(rng.randint(40, 900)),
        "week_no": str(rng.randint(1, 52)),
        "project": rng.choice(["Ridgeway", "Harbour", "Lantern", "Bluebell"]),
        "weekday": rng.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]),
        "order_no": f"VM-{rng.randint(100000, 999999)}",
        "time": rng.choice(["12:00", "15:00", "17:00"]),
    }
    subject = _render(rng.choice(family.subjects), slots, family.id)
    body = _render(rng.choice(family.bodies), slots, family.id)

    def addr(local: str, domain: str) -> str:
        return f"{local}@{domain}".lower()

    sender_person = f"{sender_first}.{sender_last}"
    brand_name = slots["brand"]
    lure_local = rng.choice(["noreply", "accounts", "support"])
    unknown_name = rng.choice(["Account Notice", "Notification Service"])
    person = f"{sender_first} {sender_last}"
    from_header = {
        "lure": f"{brand_name} <{addr(lure_local, lure_domain)}>",
        "fake_it": f"{org.it_desk} <{addr('it-support', lure_domain)}>",
        "spoofed_manager": f"{person} <{addr(sender_person + '.office', freemail)}>",
        "unknown": f"{unknown_name} <{addr('alerts', lure_domain)}>",
        "colleague": f"{person} <{addr(sender_person, org.domain)}>",
        "brand": f"{brand_name} <{addr('accounts', brand.domain if brand else org.domain)}>",
        "org_it": f"{org.it_desk} <{addr('servicedesk', org.domain)}>",
        "org_hr": f"{org.hr_team} <{addr('people', org.domain)}>",
    }[family.sender]
    recipient_addr = addr(f"{recipient_first}.{recipient_last}", org.domain)

    msg = EmailMessage(policy=default_policy)
    msg["From"] = from_header
    msg["To"] = f"{recipient_first} {recipient_last} <{recipient_addr}>"
    if family.reply_to == "lure":
        msg["Reply-To"] = addr("verify", lure_domain)
    elif family.reply_to == "freemail":
        msg["Reply-To"] = addr(sender_person, freemail)
    msg["Subject"] = subject
    msg["Date"] = format_datetime(when)
    msg["Message-ID"] = f"<{record_id}@generator.phishdesk.test>"
    msg[SYNTHETIC_HEADER] = f"true; generator={GENERATOR_VERSION}; family={family.id}; seed={seed}"
    msg.set_content(body + "\n")
    if family.attachment:
        filename = _render(family.attachment.filename, slots, family.id)
        msg.add_attachment(
            ATTACHMENT_BODY, maintype="text", subtype=family.attachment.subtype, filename=filename
        )
        msg.set_boundary(f"==phishdesk-{record_id}==")

    data = msg.as_bytes()
    record = EmailRecord(
        id=record_id,
        source="synthetic",
        source_ref=f"generator v{GENERATOR_VERSION}, family {family.id}, seed {seed}",
        licence="Apache-2.0 (project-generated)",
        redistributable=True,
        language="en",
        date=when.date(),
        template_family=family.id,
        is_phishing=is_phishing,
        category=family.category,
        tactics=family.tactics,
        label_by="generator",
        label_confidence="high",
        raw_path=f"data/raw/synthetic/{record_id}.eml",
    )
    return data, record


Plan = list[tuple[Family, int]]


def plan_per_family(
    config: GeneratorConfig, per_family: int, include_held_back: bool = False
) -> Plan:
    families = [f for f in config.families if include_held_back or not f.held_back]
    return [(f, seed) for f in families for seed in range(per_family)]


def plan_by_category(
    config: GeneratorConfig, counts: dict[Category, int], include_held_back: bool = False
) -> Plan:
    """Spread each category's count evenly over its active families."""
    plan: Plan = []
    for category, total in counts.items():
        families = [
            f
            for f in config.families
            if f.category == category and (include_held_back or not f.held_back)
        ]
        if not families:
            raise GeneratorError(f"no active families for category '{category.value}'")
        base, extra = divmod(total, len(families))
        for i, family in enumerate(families):
            plan += [(family, seed) for seed in range(base + (1 if i < extra else 0))]
    return plan


def write_dataset(config: GeneratorConfig, plan: Plan, eml_dir: Path, records_path: Path) -> int:
    """Write .eml files and a JSONL of records. Replaces previous synthetic output."""
    eml_dir.mkdir(parents=True, exist_ok=True)
    for old in eml_dir.glob("syn-*.eml"):
        old.unlink()
    records_path.parent.mkdir(parents=True, exist_ok=True)
    with open(records_path, "w", encoding="utf-8", newline="\n") as out:
        for family, seed in plan:
            data, record = generate_email(config, family, seed)
            (eml_dir / f"{record.id}.eml").write_bytes(data)
            out.write(json.dumps(record.model_dump(mode="json")) + "\n")
    return len(plan)
