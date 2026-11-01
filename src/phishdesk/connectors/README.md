# IMAP/Gmail and experimental Graph adapters

Lead: Darshan. This directory is a handoff boundary; ingest adapters are not implemented. See the v2 plan and [C04 access assessment](../../../docs/c04-feasibility.md).

The prior authorized dedicated synthetic-mailbox Gmail OAuth test retrieved one exact synthetic message/body using `gmail.readonly` with zero writes. [Sanitized provenance](../../../docs/reports/c04-gmail-sanitized.json) records the result; no mailbox connection was repeated in the final documentation task. Scope is mailbox-wide and selection was bounded by the test.

Other IMAP and OAuth negative/revocation tests remain unrun. The existing owner request for a separate non-production Microsoft 365 tenant is outstanding. Graph remains experimental/deferred at the Month 2 tenant gate. C05 retains secure credentials, deduplication, provider errors, retries and mocks; no C05 work was started. No private mailbox identifiers, credentials or OAuth material belong in repository evidence.
