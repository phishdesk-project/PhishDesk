# C03 deterministic sender and URL evidence

Issue #9; revised v2 plan sections 6, 15, 16 and 18. C02 merged through PR #100.
Evidence/ Verdict v1 schemas, parser behavior, mock API and dependencies stay
unchanged. S02 #7 still owns shared-contract review; C03 consumes the current draft.

## API and trust boundary

```python
from datetime import date
from uuid import UUID
from phishdesk.checks import CheckContext, check_eml, run_checks

context = CheckContext(as_of=date(2026, 10, 28), reference_domains=("fablebank.test",))
checked = check_eml(synthetic_bytes, case_id=UUID(int=9), context=context)
# Or enrich an existing C02 result:
checked = run_checks(parsed_evidence, context=context)
```

Both entry points return schema-valid `EvidenceV1`. Parsed fields, links,
attachments, sandbox state, earlier findings and missing states are preserved.
New finding IDs avoid every existing evidence ID; references validate before
return. Call once per parsed case: repeated enrichment is not idempotent and may
append findings. Same validated inputs/context produce identical output. No
wall-clock reads, randomness, DNS, HTTP, WHOIS/RDAP, callbacks, model calls, file
writes, content logs, link navigation or attachment execution occur in the checks.
The optional `check_eml` wrapper uses C02's bounded worker first.

Only reviewed caller code may construct `CheckContext`. Do not deserialize it
from message/model/user-controlled request data in a future API. Its
`trusted_authentication` accepts at most one `IngressAuthentication` per mechanism
(SPF, DKIM, DMARC). These are assertions by a trusted ingress adapter, not local
cryptographic verification. C03 supplies no adapter or authentication verifier.
Missing mechanisms stay `not_checked`; explicit unknown results stay `unknown`.
Trusted failures produce a referenced Suspicious finding; a pass never establishes
a safe email. No authserv-id string or header position is treated as a trust root.

`run_checks` downgrades authentication claims inside Evidence, including claimed
`trusted_ingress` provenance, to `unknown/unverified_header` unless independently
supplied in context. Original authentication IDs survive for earlier references.
Duplicate mechanisms reject the call. An existing `not_checked/not_checked`
signal remains not checked. `check_eml` scans only the bounded root header block
for Authentication-Results presence; all three mechanisms then remain unknown
with unverified-header provenance. It does not interpret header result tokens;
body/nested headers cannot establish provenance. C02 by itself still omits raw
authentication headers and returns empty authentication. C03 never promotes mail
text to a trusted result. C02's historical `authentication.not_checked` state is
preserved even when separate ingress observations are supplied.

The trust design follows [RFC 8601's trust boundary](https://www.rfc-editor.org/rfc/rfc8601.html#section-1.2).
URL splitting alone is not validation, as documented by
[Python](https://docs.python.org/3.11/library/urllib.parse.html#url-parsing-security).

## Findings and confidence

| Check | Meaning | Severity / confidence |
| --- | --- | --- |
| `c03.reply_to_mismatch` | From and Reply-To DNS domains differ after IDNA/case/trailing-dot normalization | Suspicious / 1.0 for the observed inequality |
| `c03.sender_domain` | Configured one-edit/deceptive domain or internationalized sender indicator | Suspicious / 0.6, heuristic |
| `c03.url` | Structural, configured lookalike or internationalized-host indicator | Suspicious / 0.6; unsupported/malformed syntax uses 1.0 for the syntax observation |
| `c03.authentication` | Explicit trusted ingress failure | Suspicious / 1.0 for the caller's failure observation |
| `c03.domain_age` | Valid, fresh, offline host-specific age observation | Suspicious when <30 days; otherwise informational Safe / 1.0 for date arithmetic |

Confidence describes the observation/heuristic, **not a calibrated phishing
probability**. No Dangerous finding, final safety verdict, detection-rate claim,
action proposal or remediation is produced. A Safe domain-age finding means only
that this age threshold did not fire; its detail expressly denies a safety claim.
An older domain, matching Reply-To, auth pass, HTTPS or no findings cannot prove
the message safe. Existing `validate_exchange` prevents a Verdict from lowering
the strongest finding's severity and requires visible uncertainty for missing
evidence. The demo's Verdict is explicitly scripted, with fixture confidence 0.5.

Sender comparison supports a single simple ASCII local-part mailbox, optionally
with a display name. Unsupported quoted local parts, comments, groups, lists,
domain literals, malformed addresses and missing identities remain unknown.
Comparison is by full DNS domain, so distinct legitimate service subdomains can
trigger a mismatch; different local parts on the same domain do not. Evidence v1
has no reserved Reply-To reference: the mismatch references `sender.from_address`
and names the preserved `reply_to` field in its detail. Consumers must read both
fields, escape all untrusted content, and never render raw link values as trusted
navigation. This is a contract limitation, not a new reserved reference.

Lookalikes require explicit approved reference domains (max 50). Exact domains
and proper subdomains are excluded. At the reference's label depth, one insertion,
deletion or substitution flags similarity; a reference embedded beneath another
domain flags deception. No public-suffix/registrable-domain inference or brand
ownership lookup occurs. IDNA uses Python's built-in codec; internationalized
names are indicators, not a Unicode confusable classifier. Transpositions,
arbitrary homographs, brand semantics and all lookalike variants are not covered.

URL checks inspect original bounded HTTP(S) strings before `urlsplit` can strip
controls. Whitespace, controls, backslashes, invalid scheme/host/port, invalid
A-labels and noncanonical numeric authorities stay uncertain. Checks flag HTTP,
userinfo, IP literals (IPv4 and IPv6), non-default ports, invalid percent escapes,
internationalized hosts and configured lookalikes. No canonical rewritten URL,
redirect, reachability, reputation, content or browser-equivalence claim is made.
C03 sees only links C02 extracted; omitted or unsupported schemes in raw mail
are not magically recovered. Parser omissions and limits remain visible.

## Offline domain-age observations

`DomainAgeObservation` carries exact DNS hostname, source identifier, status
(`ok/unknown/failed/timeout`), observation date and optional creation date.
`examples/checks-context.json` contains invented observations for `.test` domains;
they are not registry records. A future reviewed provider adapter can supply
observations, but no provider/network integration is included in C03 or C04.

Only an exact normalized hostname matches; no age is inferred for a subdomain
from a parent-domain record. Source and dates appear in the referenced finding's
detail. An explicit `as_of` makes results reproducible. Missing creation dates,
creation after observation, observation in the future, or an observation more
than 30 days old remain unknown. Failed/timeout/unknown observations generate
missing states and **no Safe finding**. IP literals have no inferred domain age.
Unavailable data never defaults to zero days, an old date, safety or a pass.

## Bounds, failure states and integration

C03 accepts validated Evidence v1: up to 200 links of 4096 characters, 1000-char
sender fields, 200 findings and 100 missing states. Context permits 50 references
and 200 offline age observations, each hostname at most 253 characters, and three
authentication observations. No callback can create unbounded or blocking work.
Age observations are indexed once. Host similarity is linear per reference;
work is bounded by contract counts/lengths, with no recursive address parser.
There is no additional wall-time or OS memory isolation claim for C03.

Findings beyond v1's 200-item capacity are omitted with `c03.findings_limit`;
existing findings/risk floors are preserved. Missing codes are deduplicated; if
the 100-state capacity cannot express new uncertainty the call raises a static
ValueError rather than dropping uncertainty or returning a misleading result.
Invalid/duplicate context or duplicate authentication mechanisms also reject the
call. Callers must treat these as failed checks, never fall back to a Safe verdict.

New codes are `c03.authentication.{spf,dkim,dmarc}.{unknown,not_checked}`,
`c03.authentication.unverified_header`, `c03.sender.unknown`,
`c03.reply_to.{absent,unknown}`, `c03.lookalike.not_configured`,
`c03.url.unknown`, `c03.domain_age.{not_checked,not_applicable,unknown,failed,timeout,invalid,stale}`,
and `c03.findings_limit`. Codes are aggregate case uncertainty: for example,
`c03.domain_age.not_checked` applies to hosts without a matching observation.
They are not a per-host lookup ledger; known age findings carry per-host references.

Run the standard README checks and `python -m phishdesk.checks.demo`. CI runs
the C03 demo, synthetic/contract/security tests on Python 3.11 and 3.13, plus
existing container, dependency and redacted history scans. This change does not
start mailbox/sandbox feasibility C04, intake, AI/fusion or future plugin work.
