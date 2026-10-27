from fastapi.testclient import TestClient

from phishdesk.api.app import app
from phishdesk.contracts import EvidenceV1, VerdictV1, validate_exchange


def test_mock_exchange_and_no_actions():
    with TestClient(app) as client:
        assert client.get("/health").json()["mode"] == "synthetic_mock"
        evidence = client.get("/v1/demo/evidence")
        verdict = client.get("/v1/demo/verdict")
        assert evidence.status_code == verdict.status_code == 200
        validate_exchange(
            EvidenceV1.model_validate_json(evidence.text),
            VerdictV1.model_validate_json(verdict.text),
        )
        assert client.post("/v1/actions", json={"execute": True}).status_code == 404
        assert client.get("/v1/cases").status_code == 404
