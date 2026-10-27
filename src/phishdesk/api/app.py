"""Loopback-only development mock. Never serve real case data here."""

from fastapi import FastAPI

from phishdesk.contracts import EvidenceV1, VerdictV1
from phishdesk.demo import fixture_exchange

app = FastAPI(
    title="PhishDesk synthetic mock API",
    version="0.0.0",
    description="Fixture-only development API. No authentication, real mail, models, "
    "sandbox navigation or remediation. Bind to loopback only.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "synthetic_mock"}


@app.get("/v1/demo/evidence", response_model=EvidenceV1)
def demo_evidence() -> EvidenceV1:
    return fixture_exchange()[0]


@app.get("/v1/demo/verdict", response_model=VerdictV1)
def demo_verdict() -> VerdictV1:
    return fixture_exchange()[1]
