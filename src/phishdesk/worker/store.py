"""PostgreSQL case store and job state machine. The database is the source of truth.

At-least-once brokers redeliver; idempotency comes from the guarded updates here,
not from the queue library. See docs/decisions/0002-job-queue.md.
"""

import enum
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Engine,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    and_,
    case,
    cast,
    func,
    literal,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

MAX_RAW_BYTES = 2 * 1024 * 1024  # Matches the C02 parser ceiling.
SubmissionKey = str


class JobState(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class JobKind(enum.StrEnum):
    PARSE = "parse"


def _enum(kind: type[enum.StrEnum], name: str) -> Enum:
    # Store values ("running"), not member names ("RUNNING"), so SQL reads naturally.
    return Enum(kind, name=name, values_callable=lambda members: [m.value for m in members])


class Base(DeclarativeBase):
    pass


class CaseRow(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    submission_key: Mapped[str] = mapped_column(String(200), unique=True)
    source: Mapped[str] = mapped_column(String(20))
    raw_sha256: Mapped[str] = mapped_column(String(64))
    # Plaintext reported mail. SEC05 (encryption) and C08 (retention) are not done.
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint("source IN ('synthetic', 'imap', 'gmail', 'graph')", name="case_source"),
    )


class JobRow(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    kind: Mapped[JobKind] = mapped_column(_enum(JobKind, "job_kind"))
    idempotency_key: Mapped[str] = mapped_column(String(250), unique=True)
    state: Mapped[JobState] = mapped_column(_enum(JobState, "job_state"), default=JobState.QUEUED)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Static codes only, never exception text or message content.
    error_code: Mapped[str | None] = mapped_column(String(100))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="job_max_attempts"),
        CheckConstraint("attempts BETWEEN 0 AND max_attempts", name="job_attempts"),
    )


def create_schema(engine: Engine) -> None:
    """Temporary until OPS01 adds migrations. Never use this to change a schema."""
    Base.metadata.create_all(engine)


@dataclass(frozen=True)
class Submission:
    case_id: uuid.UUID
    job_id: uuid.UUID
    created: bool


@dataclass(frozen=True)
class Claim:
    """`attempt` is the fencing token: only the current holder may finish the job."""

    job_id: uuid.UUID
    case_id: uuid.UUID
    attempt: int


class ClaimOutcome(enum.Enum):
    CLAIMED = "claimed"
    TERMINAL = "terminal"  # Already succeeded/failed: drop the duplicate message.
    BUSY = "busy"  # Another worker holds a live lease: retry the message later.
    MISSING = "missing"


@dataclass(frozen=True)
class ClaimResult:
    outcome: ClaimOutcome
    claim: Claim | None = None


def submit_case(
    session: Session,
    raw: bytes,
    *,
    source: str = "synthetic",
    submission_key: SubmissionKey | None = None,
    max_attempts: int = 3,
) -> Submission:
    """Idempotent: the same submission key returns the existing case and parse job."""
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise ValueError("Raw message must be non-empty and within the parser ceiling")
    digest = hashlib.sha256(raw).hexdigest()
    key = submission_key or f"sha256:{digest}"
    inserted = session.execute(
        insert(CaseRow)
        .values(id=uuid.uuid4(), submission_key=key, source=source, raw_sha256=digest, raw=raw)
        .on_conflict_do_nothing(index_elements=[CaseRow.submission_key])
        .returning(CaseRow.id)
    ).scalar_one_or_none()
    case_id = (
        inserted
        or session.execute(select(CaseRow.id).where(CaseRow.submission_key == key)).scalar_one()
    )
    job_key = f"{JobKind.PARSE}:{case_id}"
    session.execute(
        insert(JobRow)
        .values(
            id=uuid.uuid4(),
            case_id=case_id,
            kind=JobKind.PARSE,
            idempotency_key=job_key,
            state=JobState.QUEUED,
            attempts=0,
            max_attempts=max_attempts,
        )
        .on_conflict_do_nothing(index_elements=[JobRow.idempotency_key])
    )
    job_id = session.execute(
        select(JobRow.id).where(JobRow.idempotency_key == job_key)
    ).scalar_one()
    return Submission(case_id=case_id, job_id=job_id, created=inserted is not None)


def _seconds(value: float) -> Any:
    return func.make_interval(0, 0, 0, 0, 0, 0, value)


def _expired() -> Any:
    return and_(JobRow.state == JobState.RUNNING, JobRow.lease_until < func.now())


def claim(session: Session, job_id: uuid.UUID, *, lease_seconds: float) -> ClaimResult:
    """Atomically take a job. Concurrent callers get exactly one CLAIMED."""
    if not 0 < lease_seconds <= 3600:
        raise ValueError("Lease must be positive and at most one hour")
    # A lease that expired on the final attempt can never be retried: fail it.
    session.execute(
        update(JobRow)
        .where(JobRow.id == job_id, _expired(), JobRow.attempts >= JobRow.max_attempts)
        .values(state=JobState.FAILED, lease_until=None, error_code="job.lease_expired")
    )
    row = session.execute(
        update(JobRow)
        .where(
            JobRow.id == job_id,
            JobRow.attempts < JobRow.max_attempts,
            or_(JobRow.state == JobState.QUEUED, _expired()),
        )
        .values(
            state=JobState.RUNNING,
            attempts=JobRow.attempts + 1,
            lease_until=func.now() + _seconds(lease_seconds),
            error_code=None,
        )
        .returning(JobRow.case_id, JobRow.attempts)
    ).one_or_none()
    if row is not None:
        return ClaimResult(ClaimOutcome.CLAIMED, Claim(job_id, row.case_id, row.attempts))
    state = session.execute(select(JobRow.state).where(JobRow.id == job_id)).scalar_one_or_none()
    if state is None:
        return ClaimResult(ClaimOutcome.MISSING)
    if state in (JobState.SUCCEEDED, JobState.FAILED):
        return ClaimResult(ClaimOutcome.TERMINAL)
    return ClaimResult(ClaimOutcome.BUSY)


def _fenced(held: Claim) -> Any:
    return and_(
        JobRow.id == held.job_id,
        JobRow.state == JobState.RUNNING,
        JobRow.attempts == held.attempt,
    )


def complete(session: Session, held: Claim, result: dict[str, Any]) -> bool:
    """Record a result only if this claim still holds the job. False means superseded."""
    done = session.execute(
        update(JobRow)
        .where(_fenced(held))
        .values(state=JobState.SUCCEEDED, lease_until=None, result=result)
        .returning(JobRow.id)
    ).scalar_one_or_none()
    return done is not None


def fail(session: Session, held: Claim, code: str, *, retryable: bool) -> JobState | None:
    """Requeue if attempts remain and the failure is retryable; otherwise fail.

    Returns the new state, or None if this claim was superseded.
    """
    if not code.replace(".", "").replace("_", "").isalnum() or len(code) > 100:
        raise ValueError("Error codes must be static identifiers")
    row = session.execute(
        update(JobRow)
        .where(_fenced(held))
        .values(
            # Bound parameters arrive as text; Postgres needs the enum cast explicitly.
            state=cast(
                case(
                    (
                        and_(literal(retryable), JobRow.attempts < JobRow.max_attempts),
                        JobState.QUEUED.value,
                    ),
                    else_=JobState.FAILED.value,
                ),
                JobRow.state.type,
            ),
            lease_until=None,
            error_code=code,
        )
        .returning(JobRow.state)
    ).scalar_one_or_none()
    return row


def raw_message(session: Session, case_id: uuid.UUID) -> bytes:
    return session.execute(select(CaseRow.raw).where(CaseRow.id == case_id)).scalar_one()


@dataclass(frozen=True)
class JobStatus:
    job_id: uuid.UUID
    case_id: uuid.UUID
    state: JobState
    attempts: int
    max_attempts: int
    error_code: str | None


def job_status(session: Session, job_id: uuid.UUID) -> JobStatus | None:
    """Queued/running/succeeded/failed for C07 to expose behind authentication."""
    row = session.get(JobRow, job_id)
    if row is None:
        return None
    return JobStatus(row.id, row.case_id, row.state, row.attempts, row.max_attempts, row.error_code)


def requeue_orphans(session: Session, *, older_than_seconds: float) -> list[uuid.UUID]:
    """Queued jobs untouched for a while, for re-sending if the broker lost them.

    Nothing schedules this yet. Re-sending is safe: claim() makes duplicates no-ops.
    """
    return list(
        session.execute(
            select(JobRow.id).where(
                JobRow.state == JobState.QUEUED,
                JobRow.updated_at < func.now() - _seconds(older_than_seconds),
            )
        ).scalars()
    )
