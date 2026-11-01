# Historical automated C04 continuation - November 1, 2026

> Historical record of the earlier automated attempt. Later manual tests supersede its current-status conclusions; see [final assessment](c04-final-assessment.md) and [test record](c04-final-tests.json). Failures below remain failures of this earlier attempt. Old no-merge instructions are historical and superseded by the user's explicit independent-review authorization.

At the end of this earlier attempt, C04 remained open. Gmail read-only synthetic feasibility passed in the prior authorized run. A NEW disposable diskless VMware VM was prepared and booted, but the synthetic HTML rendering, navigation and network-containment acceptance tests remain blocked. PR #102 must remain unmerged; C05 was not started.

## Verified Gmail evidence

Reviewed the prior credential-free result and read-only test script; this continuation did not authenticate or query a mailbox again. Granted scope was exactly `https://www.googleapis.com/auth/gmail.readonly`. One message with the invented subject `[PHISHDESK TEST] Verification Email` was selected after verifying the dedicated test account and exact subject; its inline text body was read. Mailbox mutations: **0**. Attachments were not downloaded. The result records no saved bodies, headers or tokens.

The scope is mailbox-wide; the single-message bound was enforced by the test. This is not a production, IMAP, Graph or OAuth-negative-case pass. Account addresses, OAuth client/project identifiers, authorization URLs, credential files and email contents are excluded from these deliverables and GitHub updates. The source-result digest and allowlisted fields are in `c04-gmail-sanitized.json`.

## Windows and VMware inventory

Windows 11 Home 64-bit, build 26300.9818; VMware Workstation Pro 25H2, version 25.0.0 build 24995812. Installed RAM is approximately **15.7 GiB**. Initially only **1.06 GiB** was available; closing Chrome at the user's request released memory. A later preboot reading reached approximately **4.04 GiB** available. RAM remains constrained; no broad benchmark is claimed.

| Volume | Initial free space | Decision |
| --- | ---: | --- |
| C: | 173.7 GiB | New sandbox placed in this chat's workspace; under 1 MiB retained VM/fixture files, excluding existing boot ISO |
| D: | 203.1 GiB | Existing Ubuntu ISO read only; lab folders and disks not changed |
| E: | 8.5 GiB | Existing SOC storage not used |

Before this task VMware listed zero running VMs, six registered entries and five existing configurations. All five existing configurations have NAT; three also have a private virtual-network adapter. Those settings do not prove containment, and those guests were not booted or repurposed.

## New disposable sandbox and actual tests

Created a new VM in a separate new workspace folder, without cloning any existing guest or attaching any existing virtual disk. It has two vCPUs, no persistent guest disk, no configured vNIC, zero shared folders, and disabled clipboard, drag/drop, HGFS, USB, audio and 3D acceleration. Boot media and the separate inert fixture disc are read-only optical images. VMware's management/console channel was used only for this new guest; its availability does not establish total host-integration isolation.

The local Kali live ISO was rejected before boot because its digest did not match Kali's official checksum. The Ubuntu desktop ISO matched the exact official SHA-256 `4da4a0c9035da8e68a59a838674f403f0a54472c78a83b4fb7f78d03588f85a7`. Existing media files were not changed. Sources: [Ubuntu checksums](https://releases.ubuntu.com/24.04/SHA256SUMS), [Kali checksums](https://archive.kali.org/kali-images/kali-2026.2/SHA256SUMS).

The first power-on failed because VMware Authorization Service was stopped. Standard start was denied; user-authorized Windows administrator elevation then started it successfully. Its startup type and VMware networks were not changed. The service is left running.

| Test | Actual outcome |
| --- | --- |
| New diskless guest boot | PASS: Ubuntu live GUI reached at 2 GiB and 3 GiB. Live guest OS/browser versions could not be queried independently. |
| Guest framebuffer screenshot | PASS: VMware CLI captured a 1280x800 guest-only boot UI. The local Desktop-only `sandbox-boot-only.png` contains no rendered test page and is not HTML-rendering or containment evidence. |
| VMware Tools inspection | BLOCKED: heartbeat expired about 20 seconds after first reporting in both sessions; guest RPC calls timed out at 40 seconds and 15 seconds. Root cause unconfirmed; low RAM is not established as the cause. |
| Console keyboard control | NOT VERIFIED: requested shortcuts did not take the intended action. A later image showed literal `alt-f2`/`esc` text in guest search, proving some text input works. No reliable automation path was established. |
| Guest interface/route/resolver and mount preflight | BLOCKED: guest command channel unavailable. No host/private-network probes were substituted. |
| Owned local HTML rendering and 1280x720 page screenshot | BLOCKED at preflight. Inert fixture and read-only fixture ISO prepared; no browser launched. |
| Restricted navigation: other files/schemes, external/private/loopback/metadata, redirects, popups, downloads | NOT RUN. No runtime allowlist is installed or claimed. Policy design must reject these before any destination contact. |
| Network containment and boundary traffic | NOT RUN. Static config has no vNIC; guest routes and zero emitted traffic were not independently verified. This is not a containment pass. |
| Browser launch/screenshot failure, 10-second timeout and quota exhaustion | NOT RUN: browser execution never passed preflight. |
| Disposable cleanup | PASS: hard-powered off only the new diskless guest. Final VMware list reports zero running VMs; its folder has no VMDK, VMEM or VMSS. Prepared VM, inert fixture ISO and diagnostic logs remain; no destruction of an entire VM folder is claimed. |

Fixture SHA-256: `2f60343647ac98d09f8982b9db459a941d5937fdc8786ed5a07f99315239a831`. The fixture contains no scripts, forms, links or remote resources. Its CSP is defense in depth, not a network boundary.

## Existing labs and privacy

All **12 original tracked VM configuration, snapshot-metadata and VMware network-configuration files** retained their exact SHA-256, size and modification timestamp. The VMware inventory gained only the new sandbox entry. No existing guest was started; no existing virtual disk, snapshot or network was opened for mutation. This is a bounded configuration/metadata check, not a byte hash of every existing virtual disk.

No OAuth credential, token, private email, mailbox header/body or host browser profile entered the new guest, reports or repository updates. No network adapter was added, and no live URL or remediation was executed in the guest. Chrome was closed as authorized; no security tool, existing VM, lab service or network was stopped.

## Decision, blockers and plan alignment

Following v2 sections 6, 15, 16 and 18 and its no-live-URL gate: **GO for the prior bounded Gmail feasibility result and new offline VM preparation/boot; NO-GO for browser execution, live URLs or C04 completion.**

1. Establish a reliable, reviewed guest inspection/control path in this new sandbox, or replace it with another NEW verified clean live image. Do not enable NAT/bridged/host-only networking, shared folders, clipboard or broad guest access as a workaround.
2. Verify guest interfaces, IPv4/IPv6 routes, resolvers, mounts and clean profile. Then run the exact owned-file screenshot and deny-case matrix with a reviewed allowlist, normal browser sandboxing, job/time/output limits and independent boundary evidence. Discard the live session afterwards.
3. Microsoft 365 dedicated lab tenant remains unavailable; the existing owner provisioning request remains open. Graph stays experimental/deferred at the Month 2 gate. Other IMAP access and OAuth negative/revocation tests are unrun.
4. RishithaDama must review the evidence and applicable CI before any completion/merge decision. Issue #2 remains open and C05/C09 remain gated. No C05 implementation was begun.

The old 193-test pass belongs to the original research revision and is not presented as a new runtime or continuation result. This continuation changes documentation and sanitized evidence only. Final GitHub URLs, commit and check status are retained in the local Desktop report bundle after publication.
