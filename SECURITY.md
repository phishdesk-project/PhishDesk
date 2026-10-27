# Security policy

PhishDesk is currently a foundation with a synthetic mock API. There is no released,
supported production version, real phishing detector, contained browser service,
authenticated case store or remediation engine in this skeleton.

Do not put vulnerability details, private email content, tokens or exploit targets
in a public issue. For this private repository, contact the two existing maintainers
through your established private channel. Before a public beta, the owners must
enable and verify GitHub private vulnerability reporting or publish a verified
private reporting address; none is invented here. Acknowledgement/response targets
will be agreed at that gate.

Run the mock only on loopback with synthetic fixtures. It has no authentication and
must never serve real case data. A Docker container alone is not a sandbox guarantee.
No unknown live URL visits until dedicated containment tests pass. Block private and
metadata networks at DNS and every redirect; use neutral egress and a disable-visits
switch in the future sandbox design.

Model output is untrusted until validated and grounded. Missing/failed evidence is
unknown, never proof of safety. The model cannot lower deterministic risk floors,
grant approval or authorise quarantine. Future execution remains disabled by default
and requires backend policy, scoped authorised human approval, expiry, immediate
scope revalidation, idempotency, audit and restore.

Test mailbox operations only in authorised accounts. Never commit secrets or private
emails. Add retention, redaction and delete-case before v0.1. Keep multi-tenancy out
of v1.0; a single instance per client is the supported design direction.

Security CI here covers contracts, lint/types, runtime dependency audit and a
checksum-pinned Gitleaks history scan with redacted output. CodeQL is configured
conditionally for public repositories because the current private plan does not
support it. None of these checks proves containment. Image scans and broader
regressions remain tracked work.
