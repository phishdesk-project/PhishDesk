# 0002 – Job queue and idempotency model for C06

**Status:** Proposed (needs Rishitha's review)
**Date:** 2026-11-23
**Proposed by:** Darshan (Cybersecurity/backend)
**Reviewer:** Rishitha (AI/ML)
**Related issue:** C06 #12

## Context

C06 requires PostgreSQL cases, Redis, a documented Dramatiq/Celery choice, visible
queued/running/succeeded/failed states, and tests proving retries and duplicate
deliveries are idempotent. Every later pipeline stage (checks, sandbox, analysis,
campaigns, remediation) will run as a job on this mechanism, so the guarantees
matter more than the library.

## Decision

**Dramatiq with the Redis broker.** PostgreSQL, not the broker, is the source of
truth for job state.

| | Dramatiq | Celery |
| --- | --- | --- |
| Redis broker | Native, first-class | Supported; RabbitMQ is the reference broker |
| Retries, time limits, backoff | Built-in middleware, on by default | Built-in, more configuration |
| Delivery | At-least-once, acks after processing | At-least-once only with `acks_late`; default acks early |
| Size and surface | Small; one dependency tree | Large (kombu, billiard, vine, beat, canvas) |
| What we would use from Celery that Dramatiq lacks | Canvas workflows, beat scheduling, result backends: none needed in C06 | |

Celery's default early acknowledgement loses work when a worker dies mid-task,
which is the wrong default for a security tool. Dramatiq's default is right.

Either library delivers a message **at least once**, so neither makes a job
idempotent. That property is built in PostgreSQL:

1. **Submission is idempotent.** A case is keyed by a caller-supplied submission
   key (C05 will pass the provider message identity) or, by default, the SHA-256
   of the raw bytes. Resubmitting returns the existing case and job.
2. **Claiming is atomic.** One `UPDATE ... RETURNING` moves a job from `queued`
   (or `running` with an expired lease) to `running`, increments `attempts`, and
   sets `lease_until` from the database clock. Concurrent claims of one job yield
   exactly one winner.
3. **Completion is fenced.** The attempt number returned by the claim is a fencing
   token. `complete` and `fail` apply only if the job is still `running` at that
   attempt, so a slow worker whose lease expired cannot overwrite the result of
   the worker that took over.
4. **Duplicates are no-ops.** A message for a terminal job is dropped. A message
   for a job another worker holds raises `JobBusy`, so Dramatiq retries it later
   with backoff instead of dropping it.
5. **Retries are bounded by the database,** not only by the broker: `attempts`
   never exceeds `max_attempts`; the last failure, or a lease expiring on the last
   attempt, sets `failed` with a static error code.

Broker messages carry **only the job UUID**. No subject, sender, body or filename
enters Redis.

## Consequences and what this does not do

- Schema is created with `create_schema()` (SQLAlchemy `create_all`). **OPS01**
  must replace this with migrations before any schema change ships.
- Raw reported mail is stored in PostgreSQL in plaintext. **SEC05** (encryption at
  rest) and **C08** (retention, redaction, delete-case) are not done; until they
  are, use synthetic fixtures only, as everywhere else in the repo.
- States are exposed as a Python function. No HTTP route is added: the mock API is
  unauthenticated and must never serve real case data. **C07** owns the case API.
- If Redis loses a message outright, the job stays `queued` until something
  re-enqueues it. `requeue_orphans()` finds such jobs, but nothing schedules it yet.
- Swapping to Celery would change only `phishdesk/worker/actors.py`.
