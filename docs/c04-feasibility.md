# C04 mailbox access and sandbox feasibility

Current assessment: November 1, 2026 (America/Chicago). Lead: Darshan. Requested peer reviewer: RishithaDama. Source: PhishDesk Revised Eight-Month Plan v2, sections 6, 7, 8, 15, 16 and 18.

**GO for the bounded Gmail and owned-file offline feasibility spike; NO-GO for unknown live URLs and production containment.** The later manual results supersede the earlier blocked browser state. They do not turn failed automation into a pass or implement C05/C09.

The [final assessment and original acceptance mapping](reports/c04-final-assessment.md) is authoritative for current C04 results. It records the scoped owner-authorized independent review exception, closure conditions and documented deferrals. The [test record](reports/c04-final-tests.json) distinguishes visually reviewed original evidence from user-verified observations whose screenshots could not be recovered. [Screenshot evidence and hashes](reports/c04-evidence/README.md) include the original GUI render, read-only mount, unreachable route lookups, headless PNG metadata, timeout and file-size quota results. No screenshot was fabricated.

| Area | Current result | Limits |
| --- | --- | --- |
| Gmail OAuth | PASS: synthetic message/body retrieval with exactly `gmail.readonly`, zero writes | Prior authorized result reviewed; not rerun; scope is mailbox-wide; one-message bound client-enforced. [Sanitized JSON](reports/c04-gmail-sanitized.json). Other IMAP and OAuth negative/revocation tests unrun. |
| Disposable guest | PASS for offline spike: diskless Ubuntu VMware, no vNIC; user verified only loopback/no IPv4/IPv6 routes, no HGFS; read-only fixture ISO | Selected unreachable route lookups and mount are captured. No independently measured boundary traffic or production containment assurance. |
| Synthetic Firefox render | PASS: owned local file and synthetic marker visible; headless terminal output reports 1280x720 PNG | Original headless PNG unavailable; recovered GUI screenshot is separate. Fixture-copy byte identity unverified. |
| Navigation policy | User-verified PASS: active WebsiteFilter permits only owned file; explicit blocks for `/etc/hosts`, `/etc/passwd`, `example.com`, `127.0.0.1`, `169.254.169.254` | Original policy/denial captures unavailable. Redirects, popups, downloads and subresource controls untested. |
| Time/output limits | Screenshot with 10-second wrapper exits 0; forced sleep timeout exits 124; synthetic 16 KiB quota exits 153 at 16,384 bytes | Wrapper and `dd` tests do not establish hung-Firefox cleanup or Firefox-specific quota enforcement. |
| M365/Graph | Owner request recorded; tenant unavailable; Graph experimental/deferred | Month 2 tenant gate retained. No real tenant substituted or provisioning performed. |

No ingestion adapter, browser runner, external navigation or live remediation is implemented. C05 secure-provider implementation remains separate; C09/C10 must pass mandatory containment before unknown live URLs. No existing VM/lab was altered in this documentation task. Credentials and private account identifiers are excluded.

Historical reports: [initial research](reports/c04-verification.md), [earlier automated continuation](reports/c04-continuation.md). Their unavailable-resource and browser-blocked findings describe those earlier attempts only. The current user authorizes independent review and squash merge of #102 if correct and green, without claiming Rishitha approval or changing the general plan's shared ownership/review rules.
