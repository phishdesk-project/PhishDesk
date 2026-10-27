"""Export schemas/fixtures/OpenAPI deterministically; --check never writes."""

import argparse
import json
from pathlib import Path

from phishdesk.api.app import app
from phishdesk.contracts import ActionRequestV1, EvidenceV1, VerdictV1
from phishdesk.demo import fixture_exchange


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    outputs = {
        f"contracts/v1/{name}.schema.json": model.model_json_schema()
        for name, model in [
            ("evidence", EvidenceV1),
            ("verdict", VerdictV1),
            ("action-request", ActionRequestV1),
        ]
    }
    evidence, verdict = fixture_exchange()
    outputs["examples/fixtures/evidence.json"] = evidence.model_dump(mode="json")
    outputs["examples/fixtures/verdict.json"] = verdict.model_dump(mode="json")
    outputs["docs/api/openapi.json"] = app.openapi()
    stale = []
    for path, value in outputs.items():
        target = root / path
        content = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != content:
                stale.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        raise SystemExit("Stale generated files: " + ", ".join(stale))


if __name__ == "__main__":
    main()
