# C01 Step 4 verification — 2026-10-27

Lead: @k-Darshan-chowdary. Reviewer: @RishithaDama. Issue: #1 only.

Prerequisite #97 was already merged by the owner into `main` at
`0cbac05cd9e84f38f7f33a994174f6daf7a1ca39`, with Rishitha's approval.
The existing checkout had no uncommitted work; this fix branches from that merged
main as `fix/cyber-c01-verification`. No merge was performed during verification.

| Acceptance criterion | Evidence |
| --- | --- |
| FastAPI structure | `src/phishdesk/api/app.py` imports from the installed package outside the repository. `/health` returns `ok` / `synthetic_mock`; synthetic evidence/verdict validate against the contracts; real case and action routes return 404. |
| Structured, sensitive-data-free logs | Added `deploy/logging.json` and `SafeJsonFormatter`; README and Docker use that configuration. Only UTC timestamp, severity and a generic runtime event are serialized. Messages, arguments, logger names, extras, exception text and stack traces are omitted; access logging is disabled. Canary tests cover messages/args/extras/stack/exception data, application and Uvicorn loggers. A real loopback Uvicorn process emits valid JSON without the request-query canary. |
| Clean editable install | Fresh Python 3.13.1 virtual environment without system site packages: `python -m pip install -r requirements-dev.lock` and `python -m pip install --no-deps -e .` both exit 0. `pip check`: `No broken requirements found.` Installed package imports and health smoke also pass outside the checkout. |
| Lint, types, tests and PR CI | Ruff: `All checks passed!`; formatting: `21 files already formatted`; mypy: `Success: no issues found in 7 source files`; pytest: `24 passed, 1 warning in 0.72s`; contract drift and roadmap checks exit 0. `pip_audit -r requirements.lock`: `No known vulnerabilities found`. CI triggers on every PR, runs Python 3.11/3.13, these checks and demo; container smoke, runtime audit and redacted history secret scan also run. CodeQL is intentionally skipped for this private repository. New branch CI must pass before closure. |
| Safe Compose | Static inspection: only `mock-api`, published exclusively at `127.0.0.1:8000:8000`; no env/env_file/secrets, host mounts, mailbox connections or action service. Non-root Docker user, read-only filesystem, dropped capabilities and no-new-privileges. `0.0.0.0` is the container's internal listener; the host publication remains loopback. Docker is not installed locally, so local Compose runtime verification is unavailable. #97 container CI passed; the changed Docker logging setup requires this PR's container CI too. |
| Offline synthetic demo | `python -m phishdesk.demo` exits 0, emits invented FableBank `.test` evidence and Suspicious verdict with explicit missing evidence/uncertainty. Regression test blocks socket creation, DNS and connection helpers and the demo still succeeds. No mailbox or remediation code was added. |

Exact local command output is in [c01-exact-output.txt](c01-exact-output.txt).
The one warning is upstream Starlette's httpx test-client deprecation; tests pass.
It is recorded, not hidden or addressed through unrelated dependency changes.

Prior foundation CI evidence:
[Python 3.11/3.13 and container smoke](https://github.com/phishdesk-project/PhishDesk/actions/runs/40148345300),
[dependency and secret checks](https://github.com/phishdesk-project/PhishDesk/actions/runs/40148345408).
These are baseline results, not results for this fix.

The v2 PDF, roadmap JSON, milestones, dependencies, sequencing and contracts remain
unchanged (`git diff origin/main -- docs/planning` is empty; the roadmap validator
reports all 96 undated tasks and the acyclic graph valid). No Issue #8 work or
other feature implementation was started. No benchmark or production security
claim is made.

Ready for Rishitha's review once the linked fix PR's applicable checks pass.
Keep Issue #1 open until review and owner-directed merge; do not auto-merge.
