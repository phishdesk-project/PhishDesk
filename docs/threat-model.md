# Initial threat model

This is a planning baseline, not a security assessment of a finished product.

| Boundary | Threat | Required control/gate |
| --- | --- | --- |
| Email -> parser | malformed/huge/recursive MIME, hostile QR/attachments | bounded parser, fuzz and failure tests |
| Authentication headers -> evidence | spoofed Authentication-Results | trusted ingress provenance, unknown on failure |
| Message/page -> model | prompt injection, fabricated observations | separation, schema/reference validation, independent checks |
| URL -> browser | SSRF, redirects, DNS rebinding, metadata access | dedicated containment/egress tests before live URLs |
| Browser -> remote site | target confirmation/identifiers | neutral egress, token stripping where feasible, disable-visits option |
| API/UI -> case data | unauthorised reads, attacker HTML | authenticated scoped API, inert UI rendering |
| Proposal -> mailbox | model-only action, stale scope, replay | backend policy, human roles/expiry, revalidation, audit/restore |
| Storage/logs -> contributor | private email or secret disclosure | retention, redaction, deletion, synthetic fixtures |
| Plugin -> host | hostile executable contribution | review and least privilege; declarations are not isolation |

The mock has no real mail, navigation, model or action execution. It is intentionally
unauthenticated, so bind only to loopback and serve only synthetic fixtures. Future
authentication, containment and remediation controls require tracked implementation
and regression evidence. A container alone does not satisfy the sandbox gate.
