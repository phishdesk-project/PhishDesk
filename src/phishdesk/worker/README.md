# C06 case store and idempotent jobs

Lead: Darshan. Reviewer: Rishitha. Design and limits: [ADR 0002](../../../docs/decisions/0002-job-queue.md).

PostgreSQL holds cases and job state; Dramatiq on Redis delivers job IDs at least
once. Idempotency comes from guarded database updates, not from the broker.

| State | Meaning |
| --- | --- |
| `queued` | Waiting, or requeued after a retryable failure |
| `running` | Claimed under a lease; `attempts` is the fencing token |
| `succeeded` | Evidence v1 stored in `jobs.result` (may still contain missing-evidence codes) |
| `failed` | Attempts exhausted, non-retryable, or lease expired on the last attempt; static `error_code` only |

`succeeded` means the parse job ran. It never means the email is safe.

```sh
export PHISHDESK_DATABASE_URL=postgresql+psycopg://...   # never commit this
export PHISHDESK_REDIS_URL=redis://127.0.0.1:6379/0
python -m phishdesk.worker.main --create-schema           # temporary until OPS01
dramatiq phishdesk.worker.main --processes 1 --threads 2
```

Tests need a disposable database: `PHISHDESK_TEST_DATABASE_URL` (every run drops
and recreates the tables) and `PHISHDESK_TEST_REDIS_URL`. They skip locally
without them and fail in CI.

Not done here: migrations (OPS01), encryption at rest (SEC05), retention and
delete-case (C08), an authenticated status API (C07), scheduling of
`requeue_orphans()`, and Compose services for Postgres/Redis. Synthetic data only.
