"""Dramatiq binding. The only file that would change if the queue library changed.

Messages carry the job UUID and nothing else: no message content enters Redis.
"""

import uuid
from typing import Any

import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.middleware import AgeLimit, Retries, ShutdownNotifications, TimeLimit
from sqlalchemy.orm import Session, sessionmaker

from phishdesk.parsing import parse_eml
from phishdesk.worker.pipeline import DEFAULT_LEASE_SECONDS, Parser, RunOutcome, run_parse_job


def safe_middleware() -> list[dramatiq.Middleware]:
    """Explicit list. Dramatiq's default adds Prometheus whenever prometheus_client is
    installed, which serves metrics on 0.0.0.0:9191. OPS02 owns observability; until
    then nothing listens on a port. Callbacks and Pipelines are unused, so omitted."""
    return [AgeLimit(), TimeLimit(), ShutdownNotifications(), Retries()]


def make_broker(url: str) -> RedisBroker:
    return RedisBroker(url=url, middleware=safe_middleware())


class JobBusy(dramatiq.Retry):
    """Another worker holds a live lease. A Retry, so Dramatiq backs off without
    logging an expected condition as an unhandled error."""


class JobRetry(dramatiq.Retry):
    """The job failed and was requeued in the database. Raised so Dramatiq redelivers."""


def make_parse_actor(
    broker: dramatiq.Broker,
    sessions: sessionmaker[Session],
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    parser: Parser = parse_eml,
    max_retries: int = 10,
    min_backoff_ms: int = 1_000,
) -> Any:
    """Build the parse actor bound to one broker and one database."""

    def parse_case(job_id: str) -> None:
        outcome = run_parse_job(
            sessions, uuid.UUID(job_id), lease_seconds=lease_seconds, parser=parser
        )
        if outcome is RunOutcome.BUSY:
            raise JobBusy
        if outcome is RunOutcome.RETRY:
            raise JobRetry
        # SUCCEEDED, DUPLICATE, SUPERSEDED and FAILED all end this message.

    return dramatiq.actor(
        parse_case,
        actor_name="phishdesk.parse_case",
        broker=broker,
        max_retries=max_retries,
        min_backoff=min_backoff_ms,
        max_backoff=60_000,
        # Dramatiq's time limit is a backstop; the parser enforces its own 5 seconds.
        time_limit=int(lease_seconds * 1000),
        # Dramatiq ignores max_retries when retry_when is set, so bound it here too.
        retry_when=lambda retries, exc: (
            retries < max_retries and isinstance(exc, JobBusy | JobRetry)
        ),
    )
