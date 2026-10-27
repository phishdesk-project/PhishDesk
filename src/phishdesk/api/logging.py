"""Metadata-only JSON logs for the synthetic mock, including server errors."""

import json
import logging
from datetime import UTC, datetime


class SafeJsonFormatter(logging.Formatter):
    """Never serialize messages, arguments, extras, exceptions or request data."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "level": logging.getLevelName(record.levelno)
                if record.levelno in (10, 20, 30, 40, 50)
                else "UNKNOWN",
                "event": "runtime_error" if record.exc_info else "runtime_log",
            }
        )
