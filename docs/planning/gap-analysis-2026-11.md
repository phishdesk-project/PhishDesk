# Roadmap gap analysis, November 2026

Reviewed the v2 plan against the repository as it actually stands, after C01-C04
and A01 closed. This records what was added, what was deliberately **not** changed,
and the structural findings both owners should decide on together.

The v2 plan remains the baseline. Its 96 tasks are untouched: no task was removed,
renamed, re-phased, or had its dependencies rewritten. `scripts/check_roadmap.py`
now enforces that the baseline stays at 96, so a silent edit to it fails CI.

## 1. Five tasks added

The plan ended at M8 without a path to a deployable install. Five operational
concerns were absent from all 96 tasks. They are added as ordinary planned tasks
with real prerequisites, not as a separate backlog.

| Key | Phase | Deliverable | Depends on |
| --- | --- | --- | --- |
| OPS01 | M2 | Database schema migrations | C06 |
| SEC02 | M3 | Provider credentials protected at rest | C05 |
| SEC01 | M4 | Dashboard authentication and authorisation | C07 |
| OPS02 | M4 | Report rate limiting and operator observability | C06, C07 |
| SEC03 | M6 | Tamper-evident action audit log | C20 |

Why each was missing, and why it is placed where it is:

**OPS01 — migrations (M2, with C06).** C06 introduces PostgreSQL and C24 documents
backup, restore and upgrade, but nothing introduces a migration mechanism. Placed in
the same phase as C06 deliberately: every schema change after C06 needs a migration,
so adding the tool later means retrofitting migrations for work already done. A
self-hosted product that cannot move an operator's database across versions cannot
ship a second release.

**SEC02 — secrets at rest (M3, after C05).** C05 requires least-privilege credentials
"outside the repo", which states where they are not, rather than where they are. From
C05 onward a real OAuth refresh token lives on the operator's disk. Nothing covered
encryption at rest, key management, rotation, or compromise response. Placed in M3
rather than later because the exposure begins the moment C05 lands, not when the
product ships.

**SEC01 — dashboard authentication (M4, before C18).** C18 assumes role approvals and
C08 assumes a tenant gate, but no task builds the identity system those roles live in.
The C01 mock API states plainly that it has no authentication and must stay on
loopback; nothing between that and M5 adds any. For a tool that can quarantine a
user's mail, the sign-in surface is the first thing an attacker targets. Placed in M4
so it precedes C18 in M5, and to avoid loading M3 further (see section 3).

**OPS02 — rate limiting and observability (M4).** Employees submit messages and
nothing bounds that; one misconfigured forwarding rule fills the queue. Separately,
`opentelemetry-api` is a pinned dependency that nothing imports, and no task covers
health endpoints, queue depth, job failure rate or alert thresholds — all of which an
operator needs before this runs unattended.

**SEC03 — audit integrity (M6, hardening).** C20 records a redacted action audit, but
nothing establishes that the record cannot be altered afterwards. If an attacker
reaches an administrator account, the audit is what tells the operator which
quarantine actions were legitimate. An audit the same privilege level can edit cannot
answer that question.

## 2. Validator strengthened

`scripts/check_roadmap.py` previously asserted a bare `== 96`, which meant any
addition broke it and the number carried no meaning beyond itself. It now:

- separates the **v2 baseline** (96, by source string) from later additions, so the
  agreed plan is still protected while the roadmap can grow
- adds a **phase-order check**: a prerequisite may not sit in a later phase than the
  task that needs it

The phase-order check passes on the original 96, so it codifies a property the v2
plan already had rather than imposing a new one.

## 3. Findings not acted on — these need both owners

Nothing below was changed. Each is a judgement call that needs agreement, and in two
cases needs data neither of us has yet.

### 3.1 The critical path is 23 levels deep and roots at S02

```
S02 -> C02 -> C06 -> C09 -> C14 -> C15 -> C17 -> C18 -> C19 -> C20
    -> C21 -> C24 -> C25 -> C27 -> A28 -> C28 -> S13 -> C29 -> A29
    -> A32 -> C32 -> S15 -> S16
```

Every remaining deliverable traces back through S02. With two part-time owners, a slip
anywhere in that chain propagates to everything after it, and there is no parallel work
to absorb it. Twenty of the twenty-three links are cyber-led, so the chain is also
almost entirely one person's queue.

This was left alone because shortening it means rewiring prerequisites that encode real
technical constraints, and guessing at which ones are soft would be worse than the
problem. Candidate decouplings worth examining together, in rough order of promise:

- **C17/C18 (approval policy) vs C15 (remediation).** If the policy and role model can
  be specified and tested against a fake provider, they need not wait on live
  remediation.
- **C19/C20 (revalidation, audit) vs C18.** Both are arguably about recording and
  checking actions rather than approving them.
- **C24/C25 (operations, reliability) vs C21.** Documentation and recovery testing may
  not need the full chain ahead of them.

Each is a question for the person who wrote the dependency, not something to change
unilaterally.

### 3.2 M3 has no slack on the hardest task in the project

M3 holds C09 (disposable browser jobs), C10 (prove containment and neutral egress),
C11, C12, SEC02 and the protected Week 12 — eight cyber tasks in a four-week phase.

C04 established that an offline, diskless VM can render an owned local file. C10 asks
for containment against *hostile* pages: neutral egress, DNS rebinding protection,
redirect revalidation, SSRF controls, seccomp, resource quotas. That is a specialist
discipline, and it gates A11, A14 and C14 downstream.

The cut list correctly forbids cutting containment, which means if C10 runs long,
everything after it moves. **Re-budgeting this should wait for the M2 gate**, when
there is real throughput data instead of five closed tasks. Deciding now would be
guesswork dressed as planning.

A cheaper mitigation worth considering in the meantime: an external review of C10
before containment is claimed. Neither owner is independent on it — one builds it, and
it sits outside the other's track.

### 3.3 The M8 milestone is named v1.0, and the scope behind it is not

M8's gate is that a fresh reviewer can install, analyse, approve, quarantine and
restore. That is demo-complete. Behind it there is no multi-tenancy (deliberately
deferred), one remediation provider, and — until SEC01 — no authentication at all.

A version number is a claim. Calling this v1.0 invites someone to point it at real
mailboxes. Renaming the milestone to v0.9, or stating plainly in README that it is
reference-grade rather than production-grade, is consistent with the project's own
rule against claiming unmeasured success. Milestone names live in GitHub rather than
this file, so this is a change for the owners to make directly.

### 3.4 Workload

With the five additions the split is 53 cyber-led and 48 AI-led, which is balanced
overall. Per phase, cyber carries 9 of 18 tasks in M2 and 8 of 14 in both M3 and M4.
Combined with 3.1, the cyber track is both the longer queue and the critical path.

## 4. What this does not do

This does not make PhishDesk production-ready, and nothing here should be read as
claiming it. It makes the *plan* complete: the five concerns above now have owners,
prerequisites and acceptance criteria instead of being absent. The software behind
them is unwritten, and the honest statement of status remains the one in README.
