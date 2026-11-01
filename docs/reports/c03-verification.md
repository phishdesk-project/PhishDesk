# C03 verification - 2026-10-28

Issue [#9](https://github.com/phishdesk-project/PhishDesk/issues/9).
Lead: @k-Darshan-chowdary; requested reviewer: @RishithaDama.
Branch: `feature/cyber-c03-deterministic-checks`; base `6be0f9907ebb857b07bdb335e0752af82745f168`.
The requested existing Windows checkout was clean. `main` was fast-forwarded
after fetching; the base is merged C02 PR #100. No reset, discarded work or main
push was used. Issue #9 and revised v2 plan sections 6, 15, 16 and 18 were read.

## Acceptance evidence

| Criterion | Implementation and reproducible evidence |
| --- | --- |
| Reply-To mismatch, lookalikes, URL structure and domain-age checks return evidence, severity and confidence | `phishdesk.checks` enriches unchanged Evidence v1. Findings reference preserved sender/link/auth IDs and carry bounded details, severity and confidence. Domain age uses explicit offline source/dates/as-of, with a 30-day threshold; no provider is contacted. Synthetic five-case demo covers routine, mismatch/lookalike/new-age, forged authentication, URL structure and failed lookup cases. |
| Authentication provenance distinguishes trusted ingress from spoofed headers | Separate bounded `CheckContext.trusted_authentication`; serialized Evidence claims cannot establish trust. Root Authentication-Results presence remains unknown/unverified even with a trusted-looking authserv-id. Body/nested headers cannot establish root provenance. No SPF/DKIM/DMARC verification or real ingress adapter is claimed. |
| Failed lookups remain unknown and never prove safety | Missing, failed, timeout, unknown, invalid/future and stale offline observations produce explicit missing states and no Safe age finding. Unsupported addresses/URLs, parser omissions and exhausted finding budgets remain visible; saturated uncertainty capacity rejects the call. |
| C02 and Evidence v1 compatibility | Parser, models, schemas, exchange fixtures and mock OpenAPI/API unchanged. All 20 C02 fixtures pass through the enrichment and exchange validator; parsed data, existing findings, IDs, references and missing states are preserved. No lower model risk floor or invisible uncertainty allowed by exchange validation. |

Confidence 1.0 describes an observed fact/date calculation, not phishing
probability; heuristic findings use illustrative 0.6. An informational Safe age
finding only means the age threshold did not fire and explicitly denies proof of
safety. No findings or HTTPS/auth pass also cannot establish safety. This is
development regression data, not a calibrated benchmark/frozen test set.

## Final local validation

Windows Python **3.13.1**, existing `.venv` with pinned dev requirements. Every
listed command exited 0. No test was skipped or weakened.

| Command | Exact outcome |
| --- | --- |
| `python -m ruff check src tests scripts` | All checks passed! |
| `python -m ruff format --check src tests scripts` | 30 files already formatted |
| `python -m mypy` | Success: no issues found in 12 source files |
| `python -m pytest -q --basetemp=.pytest_cache/c03-final` | **193 passed, 1 warning in 18.73s** |
| `python scripts/export_contracts.py --check` | No generated schema, exchange fixture or OpenAPI drift |
| `python scripts/check_roadmap.py` | 96 undated tasks; all eight phases; cross-review and dependency graph valid |
| `python -m pip check` | No broken requirements found. |
| `python -m phishdesk.demo` | Existing synthetic exchange passes |
| `python -m phishdesk.parsing.demo tests/fixtures/mime` | 20/20 validated |
| `python -m phishdesk.checks.demo` | 5/5 C02 -> C03 -> scripted Verdict exchanges validated |
| `git diff --check` | No whitespace errors |

The warning is the pre-existing Starlette/httpx TestClient deprecation. A
restricted run stalled in an existing logging subprocess test, matching C02's
recorded Windows limitation. The complete final run used normal process access
and an explicit cache temp directory. The checks themselves remain offline.

112 new C03 regressions include identity ambiguity, Unicode/IDNA, lookalike
subdomains, malformed ports/authorities, IPv4/IPv6/noncanonical numeric hosts,
provenance spoofing, ingress overrides, stale/future/failed age observations,
maximum context/link/finding budgets, ID collisions, preserved prior risk,
network-disabled execution, privacy canaries and JSON/contract exchanges.

PR CI runs Python 3.11/3.13 checks and all three demos, container smoke, runtime
dependency audit and redacted history secret scan. Docker and Python 3.11 are not
installed locally; remote results are recorded in the linked issue/PR after the
run. CodeQL is intentionally conditional on a public repository, so it is skipped
for this private repo. No new dependency or lock change was introduced.

## Review and limits

Detailed API, provenance, bounds, static missing codes and known coverage limits:
[checks.md](../checks.md). Live lookup/ingress adapters, full mailbox grammar,
general Unicode confusable detection, public-suffix inference and production
triage are not claimed. C03 has count/length/operation bounds; no separate OS
isolation or wall-time guarantee. Re-enrichment is not idempotent; call once on
trusted parser output. Context must be built by trusted code.

S02 #7 remains the shared draft-interface review gate. C02's QR deferral remains
unchanged. C04, AI modules, mailboxes, sandbox visits and remediation are outside
this change. Issue #9 stays open/In review until the other owner's review and
merge; no self-approval, merge or automatic merge is performed. Standalone report
and exact local results are saved to the requested Windows Desktop.
