# C02 verification - 2026-10-27

Issue: [#8](https://github.com/phishdesk-project/PhishDesk/issues/8).
Lead: @k-Darshan-chowdary; reviewer: @RishithaDama.
Branch: `feature/cyber-bounded-mime-parser`, base `028e263`.
The existing Windows checkout was clean; work stayed on the user's feature branch.

| Acceptance / evidence | Result |
| --- | --- |
| Existing Evidence v1 interface | Unchanged models, schemas, API and exchange fixtures; every MIME sample round-trips through Evidence v1. Headers, plain/HTML text projection, inert URL strings, attachment labels/lengths/SHA-256 are covered. |
| Twenty synthetic `.eml` samples | 20/20 public-worker fixtures pass. Fake image bytes remain inert metadata; QR is `qr.not_run`. The original combined acceptance item stays unchecked pending agreement on the QR cut. |
| Size, recursion and time budgets | Hard message/header/part/body/decoded-byte/count/depth ceilings; iterative traversal, bounded pending siblings, strict transfer decoding, charset allowlist, static missing states. Public worker timeout includes startup and kills/waits; a real 1 ms timeout regression passes. No OS memory sandbox claim. |
| Malformed and oversized cases | Missing/unclosed boundaries, duplicate headers, invalid transfers/charset, deep multipart and message/rfc822, oversized file/message/attachment/body, URL/part/attachment counts and aggregate decoding covered. No partial attachment hash is emitted. |
| No untrusted logs or active content | Failure and HTML canaries, blocked socket/DNS helpers in worker-core regression, no attachment extraction, no image/archive/rendering library, metadata-only MIME demo. Worker output uses UTF-8 bytes on Windows. |

Final local offline checks use the existing installed Windows Python 3.13.1 dev
environment. All exit 0:

| Check | Exact result |
| --- | --- |
| `python -m ruff check src tests scripts` | `All checks passed!` |
| `python -m ruff format --check src tests scripts` | `26 files already formatted` |
| `python -m mypy` | `Success: no issues found in 10 source files` |
| `python -m pytest -q --basetemp=<local cache directory>` | `81 passed, 1 warning in 7.73s` |
| `python scripts/export_contracts.py --check` | exit 0, no drift |
| `python scripts/check_roadmap.py` | `96 undated tasks; all eight phases; cross-review and dependency graph valid` |
| `python -m pip check` | `No broken requirements found.` |
| `python -m phishdesk.demo` | exit 0, existing synthetic exchange |
| `python -m phishdesk.parsing.demo tests/fixtures/mime` | exit 0, `validated: 20`, only numeric metadata/static missing codes |
| `git diff --check` | exit 0 |

The single warning is the existing upstream Starlette/httpx TestClient deprecation.
Exact outputs are saved to the user's requested Windows Desktop as
`PhishDesk-C02-exact-results.txt`. A restricted execution environment stalled an
existing logging subprocess test and could not create pytest's default temp
directory. The complete final run used normal local execution and an explicit
cache temp directory; no tests were skipped or weakened.

CI adds the MIME demo to the existing Python 3.11/3.13 matrix. Container smoke,
fresh online vulnerability audit and redacted history secret scan remain existing
PR checks; their results must be read on the PR. Docker and Python 3.11 are not
installed locally. No new runtime/dev dependencies or lock changes were needed;
no fresh online vulnerability audit is claimed by the offline run.

Review gates: C01 (#1) is closed; S02 (#7) is still open and its draft Evidence
interface is consumed unchanged under the explicit continuation request. QR image
decoding remains deferred for bounded-decoder/dependency review. Both the handoff
and QR cut require owner review; Issue #8 stays open. No merge, real mailbox,
external URL visit, model or remediation work was performed.

Parser API, ceilings, decoding behavior and limitations: [parsing.md](../parsing.md).
