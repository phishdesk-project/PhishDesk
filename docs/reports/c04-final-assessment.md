# C04 final feasibility assessment - November 1, 2026

**GO for Month 1 owned-file offline feasibility; NO-GO for unknown live URLs or production containment.** This is a documentation/evidence update, not a browser runner or ingest implementation. It supersedes the unavailable-mailbox, no-new-VM, no-render and Step-7-blocked status as the current assessment. Earlier failed automated attempts remain historical failures; later manual results do not retroactively pass them.

## Acceptance against original Issue #2

| Original criterion | Evidence and disposition |
| --- | --- |
| Record IMAP/Gmail test-account access and request a Microsoft 365 test tenant | Met as an access spike: Gmail OAuth read-only synthetic retrieval passed with zero writes. Other IMAP is explicitly untested; Gmail IMAP's broad scope was not requested. The existing separate non-production M365 owner provisioning request remains recorded, not fulfilled. Criterion asks for a request, not a provisioned tenant. |
| Screenshot an owned synthetic page using a disposable isolated VM with private networks and credentials blocked | Met for offline feasibility: user-verified diskless/no-vNIC guest, only loopback/no routes, no HGFS, no host credentials, read-only fixture disc, recovered manual synthetic render, route/mount captures and headless PNG metadata. Exact fixture-copy byte identity and the original headless PNG are unavailable. This is not a claim of production containment or measured zero traffic. |
| Record sandbox go/no-go and disable uncontrolled navigation; no live remediation | Met at spike scope: owned-file-only WebsiteFilter active and five explicit policy denials are user-verified; original policy/denial captures were not recovered. Offline only; no live remediation or product URL runner enabled. Advanced navigation controls remain untested. |

Detailed observations, exact recovered commands, attribution and limits: [test record](c04-final-tests.json). Available screenshots, hashes and omissions: [evidence index](c04-evidence/README.md). Gmail: [sanitized result](c04-gmail-sanitized.json). No missing screenshot was reconstructed or replaced by a newly generated image.

## Verified results and limits

- Gmail: exactly `gmail.readonly`; one exact synthetic-subject message/body read, zero mailbox mutations, no attachment download. Prior result reviewed, not rerun. Scope is mailbox-wide; selection was bounded by the test.
- Offline Ubuntu VMware guest: user verified only loopback and no IPv4/IPv6 routes. Recovered route lookups for external, private and metadata-related IPv4 targets and a documentation-only IPv6 target show unreachable; no probe traffic is implied. Fixture disc is `iso9660,ro`; no HGFS mounts shown. Prior static VM evidence records no vNIC, no persistent disk, zero shares and disabled clipboard/drag-drop/HGFS/USB. No host credentials were introduced.
- Firefox manually rendered the owned inert HTML. Active WebsiteFilter permitted only the owned file and explicitly blocked `/etc/hosts`, `/etc/passwd`, `example.com`, `127.0.0.1`, `169.254.169.254` per the user's verified observations. Policy captures were not recoverable; exact original URL schemes/paths and policy bytes are not independently attested here.
- Terminal screenshot reports headless PNG 1280x720; a 10-second screenshot wrapper returned 0. Original headless PNG files are unavailable. Manual-render screenshot is separately available and visually reviewed.
- `timeout -k 2s 1s sleep 15` returned 124. This proves the wrapper test, not guaranteed termination/cleanup of a hung Firefox tree.
- A synthetic `dd` attempt to write 64 KiB under `ulimit -f 16` returned 153 with exactly 16,384 bytes, followed by a removal command. Firefox quota, CPU/memory/process limits and browser partial-output handling were not tested.

## Deferred gates under v2

The Month 1 plan section 6 asks for a sandbox feasibility spike and honest blockers. Full disposable jobs and containment are scheduled in Month 3 (section 8, C09 #21/C10 #22); they are not silently accepted by this spike. Keep independent boundary traffic measurement, DNS/redirect rebinding checks, advanced popup/download/subresource controls, normal browser security, non-root/resource limits, browser crash/failure handling, clean-profile lifecycle and process-tree cleanup as mandatory future containment work. No unknown live URLs until that gate passes. No full production containment assurance is claimed.

Microsoft 365 remains unavailable; the existing owner provisioning request is outstanding. Preserve the Month 2 tenant go/no-go (C08 #14); Graph remains experimental/deferred and C13 #31 retains that prerequisite. Other IMAP and OAuth negative/revocation tests remain unrun; C05 #11 retains secure credentials, provider failures, retries and mocks. No C05 implementation was started. C01 #1 is C04's sole prerequisite and is complete; S02 remains C05's separate dependency. Closing a feasibility spike does not pass a downstream implementation or security gate.

## Review, privacy and closure rule

The user explicitly authorized independent review and squash merge when safe, without waiting for RishithaDama. This is a scoped exception to the usual other-owner PR review requirement for #102; it does not assert Rishitha approved, remove the existing request, change equal ownership or provide cross-track architecture sign-off. Issue #2 may close only after the final evidence diff is reviewed, applicable CI passes on the exact final head and #102 merges. No automatic `Closes #2` keyword is used; closure is a separate verified step. If any of these gates fails, leave it open and identify the gate.

Only privacy-reviewed screenshots and allowlisted test records are published. Account overview and synthetic-mail UI screenshots containing mailbox identifiers are excluded and inventoried by digest; sanitized Gmail JSON supplies the bounded result. No OAuth files, token, private mailbox body/header, host profile or VM disk was collected. Evidence digests prove byte identity of recovered files, not capture time or test authenticity. No current VM lifecycle, configuration, network or service changes occurred during this final documentation task; current power state was not independently queried. Prior shutdown/preservation checks remain dated history.

New local validation: 193 tests passed (one existing Starlette/httpx deprecation warning, 18.25s); lint, format, types, contracts, roadmap, evidence hashes/links and fixture checks passed. Gitleaks 8.30.1 working-tree scan found no leaks. [Structured validation record](c04-final-validation.json). Exact reviewed head, final CI/security outcomes, merge result and issue state are recorded in the final Desktop report and GitHub review record. The historical 193-test pass is not reused as a new test result. A skipped CodeQL job is not a security pass.
