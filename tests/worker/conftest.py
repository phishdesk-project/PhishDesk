"""Worker tests run against a real PostgreSQL; idempotency depends on its semantics.

Set PHISHDESK_TEST_DATABASE_URL (a disposable database: every test drops all tables).
Locally the tests skip without it; in CI a missing database is an error, not a skip.
"""

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from phishdesk.worker.store import Base, create_schema

URL = os.environ.get("PHISHDESK_TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    if not URL:
        if os.environ.get("CI"):
            pytest.fail("PHISHDESK_TEST_DATABASE_URL must be set in CI")
        pytest.skip("PHISHDESK_TEST_DATABASE_URL not set")
    eng = create_engine(URL, pool_size=10)
    # Drop once per run, never per test: pooled connections cache enum type OIDs.
    Base.metadata.drop_all(eng)
    create_schema(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE jobs, cases"))
    return sessionmaker(engine)
