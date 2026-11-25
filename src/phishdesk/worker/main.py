"""Worker entry point: `dramatiq phishdesk.worker.main`.

Reads PHISHDESK_DATABASE_URL and PHISHDESK_REDIS_URL from the environment and
fails at startup if either is missing. Never put these values in tracked files.
Create the schema first with `python -m phishdesk.worker.main --create-schema`.
"""

import os
import sys

import dramatiq
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from phishdesk.worker.actors import make_broker, make_parse_actor
from phishdesk.worker.store import create_schema


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set")
    return value


# hide_parameters: SQLAlchemy errors otherwise embed bound values, which include
# parsed message content, and Dramatiq logs unhandled errors with their text.
engine = create_engine(
    _required("PHISHDESK_DATABASE_URL"), pool_pre_ping=True, hide_parameters=True
)
broker = make_broker(_required("PHISHDESK_REDIS_URL"))
dramatiq.set_broker(broker)
parse_case = make_parse_actor(broker, sessionmaker(engine))

if __name__ == "__main__" and sys.argv[1:] == ["--create-schema"]:
    create_schema(engine)
