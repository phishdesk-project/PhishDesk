# Draft shared contracts

Source: revised v2 plan, section 4. Both owners must review before treating v1 as
frozen. Models live in `src/phishdesk/contracts/v1.py`; generated JSON Schemas in
`contracts/v1/`; synthetic exchange fixtures in `examples/fixtures/`.

Evidence v1 flows Cyber -> AI: parsed fields, provenance-aware authentication,
links, attachment metadata, sandbox artefacts, findings and missing states.
Verdict v1 flows AI -> API: case identity, Safe/Suspicious/Dangerous label,
confidence, evidence references, uncertainty, model signals and injection flags.
ActionRequest v1 flows Campaign -> Cyber: bounded provider/mailbox/message scope,
reason/risk, mandatory approval requirement and rollback description. It is a
proposal only; there is deliberately no execution/approved field or action route.

Use `model_validate_json` at JSON boundaries and `validate_exchange` to check case
identity, evidence references, visible uncertainty and the deterministic risk floor.
Models reject unknown keys, invalid probability ranges, unsupported versions and
unbounded target scopes. Frozen tuples prevent in-place mutation of contract lists.
Schema validity does not prove semantic truth, safe HTML, a trustworthy lookup or
an authorised action. Model-produced evidence must not be trusted as deterministic
evidence. The future backend must source Evidence from its trusted check pipeline.

Regenerate with `python scripts/export_contracts.py`; CI uses `--check` to detect
drift in JSON Schemas, fixtures and the mock OpenAPI. A breaking change needs a new
version and both owners' review, with migration fixtures and compatibility notes.
