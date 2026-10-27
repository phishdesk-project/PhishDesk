"""Offline fixture demo; prints counts/static states, never message content."""

import argparse
import json
from pathlib import Path
from uuid import UUID

from phishdesk.parsing import parse_eml_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    paths = sorted(args.fixtures.glob("*.eml"))
    if len(paths) != 20:
        raise SystemExit("Expected 20 synthetic .eml fixtures")
    summaries = []
    for index, path in enumerate(paths, 1):
        evidence = parse_eml_file(path, case_id=UUID(int=index))
        if {"parser.timeout", "parser.worker_failed", "parser.malformed"}.intersection(
            evidence.missing_evidence
        ):
            raise SystemExit("Fixture worker failed")
        summaries.append(
            {
                "sample": index,
                "body_bytes": len(evidence.body_text.encode("utf-8")),
                "links": len(evidence.links),
                "attachments": len(evidence.attachments),
                "missing_evidence": evidence.missing_evidence,
            }
        )
    print(
        json.dumps(
            {"mode": "synthetic_mime", "validated": len(paths), "samples": summaries}, indent=2
        )
    )


if __name__ == "__main__":
    main()
