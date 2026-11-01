# C04 mailbox access and sandbox feasibility

Current assessment: 2026-11-01 (America/Chicago). Lead: Darshan; reviewer: RishithaDama. Issue #2 remains open; PR #102 must not merge in this task. Source: PhishDesk Revised 8-Month Plan v2, sections 6, 15, 16 and 18.

## Current decision

**Gmail read-only synthetic feasibility PASS; new offline VM prepared and booted; browser/containment acceptance BLOCKED.** This supersedes the prior Gmail-unavailable and no-new-VM findings. It does not complete C04 or unblock C05/C09.

The prior authorized test verified the dedicated synthetic account, exactly `https://www.googleapis.com/auth/gmail.readonly`, and one exact invented-subject message before reading its inline text body. Mailbox mutations were zero; no attachments downloaded; the result records no saved bodies/headers or tokens. This continuation reviewed existing evidence; it did not reconnect to a mailbox. [Allowlisted result and provenance](reports/c04-gmail-sanitized.json). The scope is mailbox-wide and the one-message restriction was enforced by the test. No production/IMAP/Graph or OAuth negative/revocation-case pass is claimed.

| Issue #2 acceptance | Current disposition |
| --- | --- |
| Record IMAP/Gmail test-account access and request Microsoft 365 test tenant | Gmail API read-only synthetic test passed. Other IMAP untested. Existing request to the project owner for a separate non-production Microsoft 365 tenant remains outstanding; no vendor signup or tenant provisioned. Await peer acceptance. |
| Screenshot owned synthetic page in disposable isolated VM with private networks/credentials blocked | NEW diskless VM with no vNIC or shares booted; guest-only boot framebuffer captured. Guest inspection/control failed. Exact owned HTML screenshot and runtime containment remain BLOCKED. |
| Sandbox go/no-go, uncontrolled navigation disabled, no live remediation | NO-GO for browser execution and live URLs; no browser launched and no runtime allowlist pass claimed. Navigation/remediation product features not added. Peer review pending. |

## New sandbox evidence and preservation

The new VM uses verified Ubuntu live read-only media, two vCPUs, no persistent disk, no configured network adapter, zero shared folders, disabled clipboard/drag/drop/HGFS/USB and a separate read-only inert fixture ISO. No existing VM was cloned, started, snapshotted or modified. The local Kali ISO was rejected on checksum mismatch; the alternate Ubuntu ISO matched the official exact-release checksum.

The stopped VMware Authorization Service initially prevented boot; user-authorized administrator elevation resolved that prerequisite without changing startup settings or networks. Ubuntu reached a live GUI at 2 and 3 GiB. In both sessions the guest-tools heartbeat expired after about 20 seconds; bounded operations timed out at 40/15 seconds. Some console text input was observed, but intended shortcut control was not established. Root cause is unknown. Browser version, guest routes/resolvers/mounts and a controlled browser job remain unverified. Static no-vNIC settings and a boot image do not establish a runtime containment pass.

The new diskless session was hard-powered off; final VMware list: zero running VMs. No VMDK, VMEM or VMSS remains in its folder. All 12 original tracked VM configuration, snapshot-metadata and VMware network-configuration files retain identical hashes, sizes and timestamps. This bounded preservation check is not a hash of every existing virtual disk. New VM registration was added to VMware inventory; existing entries preserved.

No OAuth files, private mail, host browser profile or secrets entered the new guest or these artifacts. No destination was probed and no live URL was opened in the guest. [Current detailed evidence](reports/c04-continuation.md) records actual tests, rejected media, cleanup and remaining gates. [Earlier research verification](reports/c04-verification.md) is historical; its 193-test result is not a new continuation result.

## Mail-provider limits and owner request

Gmail API `gmail.readonly` is the approved body-read feasibility path for the dedicated synthetic mailbox. Gmail IMAP requires the broad full-mail OAuth scope and was not requested. No app-password, domain-wide delegation, send/modify/delete capability or regular private mailbox access was used. Other IMAP feasibility remains untested; any later test must use an owned lab mailbox, verified TLS and read-only folder access with bounded non-mutating reads.

The existing owner request is for an owned, separate, non-production Microsoft 365 tenant with an Exchange Online synthetic-only mailbox and an administrator able to confirm licensing and delegated-access policy. No account identifiers, credentials, purchase or external vendor submission is needed in this PR. Tenant availability remains blocked; Graph is experimental/deferred at the Month 2 gate. No production or education tenant is substituted.

## Required next evidence

Keep the new sandbox offline and establish a reviewed guest-control path. Before browser launch, independently verify no non-loopback interface/route, no usable resolver or host mount, clean profile and no credentials. Permit only the exact immutable owned fixture. Reject other file paths and schemes, external/private/loopback/metadata navigation, redirects, popups, resources and downloads before contact. Keep normal browser security, one bounded job, 1280x720 screenshot, 10-second runtime and bounded output. Record launch/screenshot failure, timeout and quota exhaustion explicitly; stop rather than fall back to the host browser or networking. Measure boundary traffic independently, review the synthetic image, then discard the session.

None of those runtime deny, traffic or browser-failure cases passed in this continuation. No unknown/live URL may run before containment passes. C01 is the sole C04 prerequisite and is completed; AI implementation is independent. RishithaDama cross-review and applicable CI remain required. C05/C09 stay gated; no C05 work or merge is authorized here.
