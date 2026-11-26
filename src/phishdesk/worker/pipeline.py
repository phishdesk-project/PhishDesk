"""Broker-independent job execution. Actors stay thin so the queue library can change."""

import enum
import uuid
from collections.abc import Callable

from sqlalchemy.orm import Session, sessionmaker

from phishdesk.contracts import EvidenceV1
from phishdesk.parsing import parse_eml
from phishdesk.worker import store

Parser = Callable[..., EvidenceV1]
# Must exceed the C02 parser's 5-second wall-clock ceiling with margin.
DEFAULT_LEASE_SECONDS = 60.0


class RunOutcome(enum.Enum):
    SUCCEEDED = "succeeded"
    DUPLICATE = "duplicate"  # Terminal or unknown job: drop the message.
    BUSY = "busy"  # Live lease held elsewhere: the broker should retry later.
    SUPERSEDED = "superseded"  # Our lease expired and another worker took over.
    RETRY = "retry"  # Failed, requeued in the database; the broker should retry.
    FAILED = "failed"  # Failed for good; do not retry.


def run_parse_job(
    sessions: sessionmaker[Session],
    job_id: uuid.UUID,
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
    parser: Parser = parse_eml,
) -> RunOutcome:
    """Claim, parse outside any transaction, then record the result under the fence."""
    with sessions.begin() as session:
        result = store.claim(session, job_id, lease_seconds=lease_seconds)
    if result.outcome is store.ClaimOutcome.BUSY:
        return RunOutcome.BUSY
    if result.claim is None:
        return RunOutcome.DUPLICATE
    held = result.claim
    try:
        with sessions.begin() as session:
            raw = store.raw_message(session, held.case_id)
        # parse_eml is bounded and never raises for hostile input: failures come back
        # as Evidence with static missing-evidence codes, which is a valid result.
        evidence = parser(raw, case_id=held.case_id)
        payload = evidence.model_dump(mode="json")
        with sessions.begin() as session:
            done = store.complete(session, held, payload)
        return RunOutcome.SUCCEEDED if done else RunOutcome.SUPERSEDED
    except Exception:
        # Infrastructure failure (database, worker process). Record a static code only.
        with sessions.begin() as session:
            state = store.fail(session, held, "job.exception", retryable=True)
        if state is None:
            return RunOutcome.SUPERSEDED
        return RunOutcome.RETRY if state is store.JobState.QUEUED else RunOutcome.FAILED
