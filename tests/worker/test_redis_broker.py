"""End-to-end through a real Redis broker: duplicate sends still parse exactly once."""

import os
import time
from pathlib import Path
from typing import Any

import dramatiq
import pytest

from phishdesk.worker import store
from phishdesk.worker.actors import make_parse_actor

REDIS_URL = os.environ.get("PHISHDESK_TEST_REDIS_URL")
RAW = (Path(__file__).resolve().parents[1] / "fixtures" / "mime" / "03-base64.eml").read_bytes()


@pytest.fixture
def redis_broker() -> Any:
    if not REDIS_URL:
        if os.environ.get("CI"):
            pytest.fail("PHISHDESK_TEST_REDIS_URL must be set in CI")
        pytest.skip("PHISHDESK_TEST_REDIS_URL not set")
    from dramatiq.brokers.redis import RedisBroker

    from phishdesk.worker.actors import safe_middleware

    broker = RedisBroker(
        url=REDIS_URL, namespace=f"phishdesk-test-{os.getpid()}", middleware=safe_middleware()
    )
    broker.flush_all()
    yield broker
    broker.flush_all()
    broker.close()


def test_duplicate_sends_through_redis_parse_once(sessions: Any, redis_broker: Any) -> None:
    calls: list[str] = []

    def parser(raw: bytes, *, case_id: Any) -> Any:
        from phishdesk.parsing import parse_eml

        calls.append(str(case_id))
        return parse_eml(raw, case_id=case_id)

    actor = make_parse_actor(redis_broker, sessions, parser=parser)
    with sessions.begin() as s:
        sub = store.submit_case(s, RAW)
    for _ in range(3):
        actor.send(str(sub.job_id))
    worker = dramatiq.Worker(redis_broker, worker_threads=2, worker_timeout=100)
    worker.start()
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with sessions() as s:
                state = store.job_status(s, sub.job_id)
            if state and state.state is store.JobState.SUCCEEDED:
                break
            time.sleep(0.1)
        redis_broker.join(actor.queue_name, timeout=20_000)
    finally:
        worker.stop()
    assert calls == [str(sub.case_id)]
    with sessions() as s:
        final = store.job_status(s, sub.job_id)
    assert final is not None and final.state is store.JobState.SUCCEEDED
