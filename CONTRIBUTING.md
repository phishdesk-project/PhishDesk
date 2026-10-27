# Contributing

Darshan (@k-Darshan-chowdary) leads cybersecurity/backend. Rishitha (@RishithaDama)
leads AI/ML and the React dashboard. They are equal owners. Contracts, reviews,
documentation, releases and community work are shared.

Start with the [Roadmap](https://github.com/orgs/phishdesk-project/projects/1/views/2)
and a scoped issue. Each issue names one lead, the other owner as reviewer,
source package, dependencies, acceptance criteria and evidence needed to finish.
Month/week numbers are relative sequencing; no calendar deadlines are set.

1. Check prerequisites and agree the interface/fixture handoff.
2. Branch from current main: `feature/cyber-*`, `feature/ai-*`,
   `feature/contracts-*`, `fix/*` or `docs/*`. Keep branches short-lived.
3. Install with `python -m pip install -r requirements-dev.lock`, then
   `python -m pip install --no-deps -e .`. Run the checks in the README.
4. Update docs, fixtures and tests for success, failure, unknown and permission paths.
5. Open a PR and obtain the other owner's review with passing checks. An owner
   must never approve their own work. Squash merge after review; do not push to main.
6. Move Backlog -> In progress -> In review -> Done and close only after reviewed
   evidence or merge. Link the issue in the PR; do not close roadmap work just
   because a skeleton exists.

CODEOWNERS preserves both existing teams. Ordering identifies track lead but
either listed owner can satisfy GitHub's native code-owner rule; this cannot
enforce review by the other owner. The current private repository plan does not
support rulesets/branch protection or automatic CODEOWNERS enforcement. Follow
cross-review manually until the owners choose an appropriate plan/settings.

Every change must work locally and in an integration fixture, validate contracts,
pass applicable unit/security/regression checks, update docs/examples, contain no
secrets/private emails and have review from the other owner. Benchmark claims need
measurements, pinned model/hardware/configuration and failure analysis.

Use synthetic data with invented brands and `.test` domains, or licensed public
data with provenance. Never commit employee emails, credentials, trained model
binaries, private mailboxes or raw sandbox captures. Use runtime secrets outside Git.
Review executable plugin code: permission declarations do not sandbox it.

Follow available capacity, around 70% of theoretical time. Protect relative Weeks
12 and 24 for integration. From Month 2, each owner budgets about 2-3 hours per
working week for community work with a 48-hour reply target. Adapt meeting times
to free time: planning, runnable demo, fortnightly integration and monthly gate.

Apache-2.0 is already present and is preserved. DCO is a proposal for both owners
to decide after university/IP review; no new legal sign-off or CLA is imposed by
this setup. Do not add Signed-off-by for somebody else.
