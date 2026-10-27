import json
import logging
from pathlib import Path

import pytest

from phishdesk.api.logging import SafeJsonFormatter


@pytest.mark.parametrize("with_exception", [False, True])
def test_sensitive_messages_args_extras_and_exceptions_are_not_logged(with_exception):
    # Invented canaries only; no real mail or credentials.
    secret = "synthetic-token-canary"
    email = "private-subject-and-body-canary"
    record = logging.LogRecord(secret, logging.ERROR, email, 1, "%s %s", (secret, email), None)
    record.authorization = secret
    record.stack_info = email
    if with_exception:
        try:
            raise ValueError(email)
        except ValueError:
            import sys

            record.exc_info = sys.exc_info()
    output = SafeJsonFormatter().format(record)
    assert secret not in output and email not in output
    data = json.loads(output)
    assert set(data) == {"timestamp", "level", "event"}
    assert data["event"] == ("runtime_error" if with_exception else "runtime_log")


def test_documented_server_configuration_is_safe_including_error_and_access_logs():
    # A subprocess avoids modifying pytest's own logging handlers.
    import subprocess
    import sys

    config = Path(__file__).resolve().parents[1] / "deploy/logging.json"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import logging, logging.config, json, sys; "
            "logging.config.dictConfig(json.load(open(sys.argv[1]))); "
            "logging.getLogger('uvicorn.error').error('synthetic-token-canary'); "
            "logging.getLogger('phishdesk').info('private-body-canary'); "
            "logging.getLogger('uvicorn.access').info('private-url-canary')",
            str(config),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["level"] for line in lines] == ["ERROR", "INFO"]
    assert "canary" not in result.stderr
