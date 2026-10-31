"""Shared data-safety checks: reserved test domains and real-brand detection.

Used by the synthetic generator tests and the fixture hygiene tests, so both
apply exactly the same rule.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

# example.com/.org/.net and the .test/.example top-level names are reserved for
# testing and documentation; they can never belong to a real organisation.
_RESERVED = re.compile(r"(^|\.)(example\.(com|org|net)|[a-z0-9-]+\.test|[a-z0-9-]+\.example)$")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
_SENDER = re.compile(r"(?:sender|list):([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

# Real brands commonly impersonated in phishing. Synthetic data must never use them.
REAL_BRANDS: tuple[str, ...] = (
    "microsoft",
    "office 365",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "paypal",
    "netflix",
    "docusign",
    "dropbox",
    "adobe",
    "linkedin",
    "facebook",
    "instagram",
    "whatsapp",
    "dhl",
    "fedex",
    "ups",
    "usps",
    "wells fargo",
    "chase",
    "bank of america",
    "hsbc",
    "barclays",
    "citibank",
    "contoso",
    "fabrikam",
    "northwind",
)
_BRAND_PATTERNS = [re.compile(rf"\b{re.escape(b)}\b", re.IGNORECASE) for b in REAL_BRANDS]


def is_reserved_domain(domain: str) -> bool:
    return bool(_RESERVED.search(domain.lower().rstrip(".")))


def find_domains(text: str) -> Iterator[str]:
    """Domains appearing in email addresses, URLs and sender:/list: group names."""
    for pattern in (_EMAIL, _URL, _SENDER):
        for match in pattern.finditer(text):
            yield match.group(1).lower().rstrip(".")


def unreserved_domains(text: str) -> list[str]:
    return sorted({d for d in find_domains(text) if not is_reserved_domain(d)})


def real_brands_in(text: str) -> list[str]:
    return [b for b, p in zip(REAL_BRANDS, _BRAND_PATTERNS, strict=True) if p.search(text)]
