"""C06 acceptance: persisted cases, visible states, idempotent retries and redelivery."""

import json
import threading
import uuid
from pathlib import Path
from typing import Any

import dramatiq
import pytest
from dramatiq.brokers.stub import StubBroker
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from phishdesk.contracts import EvidenceV1
from phishdesk.parsing import parse_eml
from phishdesk.worker import store
from phishdesk.worker.actors import make_broker, make_parse_actor, safe_middleware
from phishdesk.worker.pipeline import RunOutcome, run_parse_job

MIME = Path(__file__).resolve().parents[1] / "fixtures" / "mime"
RAW = (MIME / "01-plain.eml").read_bytes()


class CountingParser:
    """Real C02 parser, counted; optionally fails its first N calls."""

    def __init__(self, fail_first: int = 0) -> None:
        self.calls = 0
        self.fail_first = fail_first
        self.lock = threading.Lock()

    def __call__(self, raw: bytes, *, case_id: uuid.UUID) -> EvidenceV1:
        with self.lock:
            self.calls += 1
            calls = self.calls
        if calls <= self.fail_first:
            raise RuntimeError("simulated infrastructure failure")
        return parse_eml(raw, case_id=case_id)


def submit(sessions: sessionmaker[Session], raw: bytes = RAW, **kw: Any) -> store.Submission:
    with sessions.begin() as s:
        return store.submit_case(s, raw, **kw)


def status(sessions: sessionmaker[Session], job_id: uuid.UUID) -> store.JobStatus:
    with sessions() as s:
        result = store.job_status(s, job_id)
    assert result is not None
    return result


def expire_lease(sessions: sessionmaker[Session], job_id: uuid.UUID) -> None:
    with sessions.begin() as s:
        s.execute(
            update(store.JobRow)
            .where(store.JobRow.id == job_id)
            .values(lease_until=func.now() - func.make_interval(0, 0, 0, 0, 0, 0, 1))
        )


def claim(sessions: sessionmaker[Session], job_id: uuid.UUID) -> store.ClaimResult:
    with sessions.begin() as s:
        return store.claim(s, job_id, lease_seconds=60)


# Submission -------------------------------------------------------------------------


def test_resubmitting_the_same_message_returns_the_same_case_and_job(sessions: Any) -> None:
    first, second = submit(sessions), submit(sessions)
    assert first.created and not second.created
    assert (first.case_id, first.job_id) == (second.case_id, second.job_id)
    with sessions() as s:
        assert s.scalar(select(func.count()).select_from(store.CaseRow)) == 1
        assert s.scalar(select(func.count()).select_from(store.JobRow)) == 1
    assert status(sessions, first.job_id).state is store.JobState.QUEUED


def test_an_explicit_submission_key_wins_over_content(sessions: Any) -> None:
    a = submit(sessions, RAW, submission_key="gmail:msg-1")
    b = submit(sessions, (MIME / "02-utf8.eml").read_bytes(), submission_key="gmail:msg-1")
    assert a.case_id == b.case_id and not b.created


@pytest.mark.parametrize("raw", [b"", b"x" * (store.MAX_RAW_BYTES + 1)])
def test_empty_or_oversized_raw_is_rejected(sessions: Any, raw: bytes) -> None:
    with pytest.raises(ValueError), sessions.begin() as s:
        store.submit_case(s, raw)


# Running ----------------------------------------------------------------------------


def test_a_job_moves_queued_running_succeeded_with_valid_evidence(sessions: Any) -> None:
    sub = submit(sessions)
    held = claim(sessions, sub.job_id)
    assert held.outcome is store.ClaimOutcome.CLAIMED
    assert status(sessions, sub.job_id).state is store.JobState.RUNNING
    with sessions.begin() as s:
        assert store.complete(s, held.claim, {"ok": True})  # type: ignore[arg-type]
    assert status(sessions, sub.job_id).state is store.JobState.SUCCEEDED

    sub2 = submit(sessions, (MIME / "02-utf8.eml").read_bytes())
    assert run_parse_job(sessions, sub2.job_id) is RunOutcome.SUCCEEDED
    with sessions() as s:
        result = s.get(store.JobRow, sub2.job_id).result  # type: ignore[union-attr]
    evidence = EvidenceV1.model_validate_json(json.dumps(result))
    assert evidence.case_id == sub2.case_id


def test_parser_failure_evidence_is_a_successful_job_not_a_safe_email(sessions: Any) -> None:
    sub = submit(sessions, (MIME / "14-unclosed.eml").read_bytes())
    assert run_parse_job(sessions, sub.job_id) is RunOutcome.SUCCEEDED
    with sessions() as s:
        stored = s.get(store.JobRow, sub.job_id).result  # type: ignore[union-attr]
    evidence = EvidenceV1.model_validate_json(json.dumps(stored))
    assert evidence.missing_evidence  # Uncertainty survives persistence.


# Duplicate delivery -----------------------------------------------------------------


def test_redelivery_after_success_is_a_no_op(sessions: Any) -> None:
    sub, parser = submit(sessions), CountingParser()
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.SUCCEEDED
    for _ in range(3):
        assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.DUPLICATE
    assert parser.calls == 1


def test_concurrent_claims_have_exactly_one_winner(sessions: Any) -> None:
    sub = submit(sessions)
    barrier, results = threading.Barrier(8), []

    def worker() -> None:
        barrier.wait()
        results.append(claim(sessions, sub.job_id).outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(store.ClaimOutcome.CLAIMED) == 1
    assert results.count(store.ClaimOutcome.BUSY) == 7
    assert status(sessions, sub.job_id).attempts == 1


def test_a_live_lease_reports_busy_so_the_broker_retries_later(sessions: Any) -> None:
    sub = submit(sessions)
    claim(sessions, sub.job_id)
    assert run_parse_job(sessions, sub.job_id) is RunOutcome.BUSY


def test_unknown_job_is_dropped(sessions: Any) -> None:
    assert run_parse_job(sessions, uuid.uuid4()) is RunOutcome.DUPLICATE


# Leases and fencing -----------------------------------------------------------------


def test_expired_lease_is_taken_over_and_the_stale_worker_is_fenced_out(sessions: Any) -> None:
    sub = submit(sessions)
    stale = claim(sessions, sub.job_id).claim
    expire_lease(sessions, sub.job_id)
    fresh = claim(sessions, sub.job_id).claim
    assert stale and fresh and (stale.attempt, fresh.attempt) == (1, 2)
    with sessions.begin() as s:
        assert not store.complete(s, stale, {"from": "stale"})
        assert store.fail(s, stale, "job.exception", retryable=True) is None
        assert store.complete(s, fresh, {"from": "fresh"})
    with sessions() as s:
        assert s.get(store.JobRow, sub.job_id).result == {"from": "fresh"}  # type: ignore[union-attr]


def test_lease_expiring_on_the_last_attempt_fails_the_job(sessions: Any) -> None:
    sub = submit(sessions, max_attempts=1)
    claim(sessions, sub.job_id)
    expire_lease(sessions, sub.job_id)
    assert claim(sessions, sub.job_id).outcome is store.ClaimOutcome.TERMINAL
    final = status(sessions, sub.job_id)
    assert (final.state, final.error_code) == (store.JobState.FAILED, "job.lease_expired")


# Retries ----------------------------------------------------------------------------


def test_a_transient_failure_retries_then_succeeds(sessions: Any) -> None:
    sub, parser = submit(sessions), CountingParser(fail_first=1)
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.RETRY
    queued = status(sessions, sub.job_id)
    assert (queued.state, queued.error_code) == (store.JobState.QUEUED, "job.exception")
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.SUCCEEDED
    done = status(sessions, sub.job_id)
    assert (done.state, done.attempts, done.error_code) == (store.JobState.SUCCEEDED, 2, None)


def test_retries_stop_at_max_attempts(sessions: Any) -> None:
    sub, parser = submit(sessions, max_attempts=2), CountingParser(fail_first=99)
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.RETRY
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.FAILED
    assert run_parse_job(sessions, sub.job_id, parser=parser) is RunOutcome.DUPLICATE
    final = status(sessions, sub.job_id)
    assert (final.state, final.attempts, parser.calls) == (store.JobState.FAILED, 2, 2)


def test_error_codes_must_be_static_identifiers(sessions: Any) -> None:
    sub = submit(sessions)
    held = claim(sessions, sub.job_id).claim
    assert held is not None
    with pytest.raises(ValueError), sessions.begin() as s:
        store.fail(s, held, "boom: Subject was 'Your invoice'", retryable=False)


def test_queued_jobs_can_be_found_for_requeue(sessions: Any) -> None:
    sub = submit(sessions)
    with sessions() as s:
        assert store.requeue_orphans(s, older_than_seconds=3600) == []
    with sessions.begin() as s:
        s.execute(
            update(store.JobRow).values(updated_at=func.now() - func.make_interval(0, 0, 0, 0, 2))
        )
    with sessions() as s:
        assert store.requeue_orphans(s, older_than_seconds=3600) == [sub.job_id]


# Through Dramatiq --------------------------------------------------------------------


def test_duplicate_broker_messages_parse_once(sessions: Any) -> None:
    broker, parser = StubBroker(middleware=safe_middleware()), CountingParser()
    broker.emit_after("process_boot")
    actor = make_parse_actor(broker, sessions, parser=parser)
    sub = submit(sessions)
    for _ in range(3):
        actor.send(str(sub.job_id))
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()
    try:
        broker.join(actor.queue_name, fail_fast=True)
        worker.join()
    finally:
        worker.stop()
    assert parser.calls == 1
    assert status(sessions, sub.job_id).state is store.JobState.SUCCEEDED


def test_broker_messages_carry_only_the_job_id(sessions: Any) -> None:
    broker = StubBroker(middleware=safe_middleware())
    actor = make_parse_actor(broker, sessions)
    sub = submit(sessions)
    message = actor.send(str(sub.job_id))
    assert message.args == (str(sub.job_id),) and message.kwargs == {}
    assert RAW[:40] not in message.encode()


def test_retry_predicate_respects_max_retries(sessions: Any) -> None:
    from phishdesk.worker.actors import JobBusy

    actor = make_parse_actor(StubBroker(middleware=safe_middleware()), sessions, max_retries=2)
    retry_when = actor.options["retry_when"]
    assert retry_when(0, JobBusy()) and retry_when(1, JobBusy())
    assert not retry_when(2, JobBusy())
    assert not retry_when(0, RuntimeError())


def test_a_non_retryable_failure_fails_immediately(sessions: Any) -> None:
    sub = submit(sessions, max_attempts=3)
    held = claim(sessions, sub.job_id).claim
    assert held is not None
    with sessions.begin() as s:
        assert store.fail(s, held, "job.invalid_input", retryable=False) is store.JobState.FAILED
    assert claim(sessions, sub.job_id).outcome is store.ClaimOutcome.TERMINAL


def test_a_job_with_exhausted_attempts_is_never_claimed_again(sessions: Any) -> None:
    sub = submit(sessions, max_attempts=2)
    with sessions.begin() as s:
        s.execute(update(store.JobRow).values(attempts=2, state=store.JobState.QUEUED))
    assert claim(sessions, sub.job_id).outcome is not store.ClaimOutcome.CLAIMED
    assert status(sessions, sub.job_id).attempts == 2


def test_no_middleware_opens_a_metrics_port() -> None:
    names = {type(m).__name__ for m in make_broker("redis://127.0.0.1:1/0").middleware}
    assert "Prometheus" not in names
    assert "Retries" in names
