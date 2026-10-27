# PhishDesk
Open-source, self-hosted phishing triage and response platform with AI-powered analysis, secure sandboxing, campaign detection, and human-approved remediation.

## Current state

**Foundation only; all product capabilities below are planned.** This branch adds
draft contracts, a safe offline synthetic demo and a fixture-only mock API so both
owners can begin in parallel. It does not yet ingest mail, detect phishing, visit
URLs, authenticate real cases, run a model or execute mailbox actions.

Darshan (@k-Darshan-chowdary) leads cybersecurity/backend. Rishitha (@RishithaDama)
leads AI/ML and the React dashboard. Ownership is equal; reviews, contracts,
documentation, releases and community work are shared.

## Start here

- [Roadmap: all eight phases](https://github.com/orgs/phishdesk-project/projects/1/views/2)
- [Assigned issues and progress](https://github.com/phishdesk-project/PhishDesk/issues)
- [Eight release milestones](https://github.com/phishdesk-project/PhishDesk/milestones)
- [Plan, gates, dependencies and cut list](docs/planning/README.md)
- [Contributing and cross-review](CONTRIBUTING.md), [security](SECURITY.md),
  [draft contracts](docs/contracts.md), [evaluation](docs/evaluation.md)

Month 1-8 and Week 1-32 are **relative sequencing only**, with no calendar start
dates or deadlines. Work at available free-time capacity. Keep Weeks 12 and 24 for
integration/buffer and keep around 30% capacity free. Nothing is marked complete
merely because it appears in the plan.

## Run the synthetic demo

Use Python 3.11+ (CI checks 3.11 and 3.13):

```sh
python -m venv .venv
# Windows PowerShell: .venv/Scripts/Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
python -m phishdesk.demo
```

The output is one invented FableBank `.test` message, schema-valid Evidence and
a fixed **Suspicious** Verdict with explicit uncertainty. Confidence `0.5` is an
illustrative fixture value, not a measured probability or benchmark result.
The command performs no model calls, network requests or mailbox actions.

For Rishitha's dashboard development:

```sh
uvicorn phishdesk.api.app:app --host 127.0.0.1 --port 8000 --no-access-log --log-config deploy/logging.json
```

Open `http://127.0.0.1:8000/docs`. Available routes are `/health`,
`/v1/demo/evidence` and `/v1/demo/verdict`. The [OpenAPI snapshot](docs/api/openapi.json)
and [JSON fixtures](examples/fixtures) can be used without a running backend.
This mock has no authentication: bind to loopback and use synthetic fixtures only.
The real case API and React implementation remain planned issues.

Use the logging configuration above for the mock server. It writes JSON metadata
only (UTC timestamp, level, generic runtime event). Messages, arguments, extras,
exception text/tracebacks and request data are deliberately omitted; access logs
are disabled. Do not add credentials or email content to logs. The offline demo
prints its explicitly synthetic fixture to stdout; it is not a real-mail CLI.

Optional Docker mock:

```sh
docker compose up --build
```

It exposes only `127.0.0.1:8000`, runs as non-root with a read-only filesystem and
has no provider credentials. This is a development mock, not a production install
or a contained browser sandbox.

## Checks before a pull request

```sh
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy
python -m pytest -q
python scripts/export_contracts.py --check
python scripts/check_roadmap.py
python -m pip_audit -r requirements.lock
```

After an intentional contract change, run `python scripts/export_contracts.py`,
review the generated diff and obtain both owners' review. Runtime/dev dependencies
are pinned in separate lock files; update them deliberately with compatibility and
security checks. Workflow actions are pinned to official commit revisions.

## Planned v1.0 scope

IMAP and Gmail intake, defensive parsing and deterministic checks, a contained
browser service, AI classification and injection-hardened analysis, corroborated
brand matching, campaign clustering, analyst dashboard, versioned plugin API and
reproducible benchmarks. Quarantine/restore covers **one** provider with backend
policy and authorised human approval; the second is experimental. Graph is at
least experimental, subject to the Month 2 test-tenant gate.

Multi-tenancy is deferred; document one instance per client. Inbound gateway,
real-time filtering, antivirus and awareness training are out of scope. Never
cut containment, approvals, privacy/redaction, contracts/tests or honest reporting.
Model output cannot authorise actions or override deterministic safeguards; failed
lookups remain unknown. No unknown live URL visits until containment is proven.

## Repository map

| Path | Lead and purpose |
| --- | --- |
| `src/phishdesk/contracts/`, `contracts/v1/` | Shared versioned models and schemas |
| `src/phishdesk/api/` | Darshan; synthetic mock now, real API later |
| `parsing/`, `checks/`, `connectors/`, `worker/`, `remediation/` under `src/phishdesk/` | Darshan; future implementation boundaries |
| `src/phishdesk/analysis/`, `campaigns/`, `bench/`, `brands/` | Rishitha; AI and evaluation boundaries |
| `web/` | Rishitha; React dashboard boundary |
| `sandbox/`, `deploy/` | Darshan; containment and operations boundaries |
| `tests/`, `examples/`, `docs/` | Shared fixtures, checks and handoffs |

Apache-2.0 is preserved. See [governance](docs/governance.md) for the unsigned
ownership/decision checklist. The repository remains private. No invitation,
public launch, signed agreement or production release is implied by this setup.
