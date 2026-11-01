# C04 mailbox access and sandbox feasibility

Assessment date: 2026-11-01 (America/Chicago). Lead: Darshan;
peer reviewer: RishithaDama. Research and preparation only; C04 is not complete.
Tracks [Issue #2](https://github.com/phishdesk-project/PhishDesk/issues/2).

## Decision and acceptance

**NO-GO for connected mailbox tests and browser execution in the available
environment.** The owner confirmed on 2026-11-01 that no dedicated Gmail/IMAP
test mailbox, Microsoft 365 test tenant or approved disposable lab VM is available.
Record these as **BLOCKED: resource unavailable**, rather than awaiting inventory
confirmation. Existing VM configurations do not establish disposable, credential-free
isolation. Do not start those guests or use the signed-in host browser for the
synthetic sandbox spike. No containment or successful mailbox-access claim is made.

The live issue and native relationship list C01 #1 as the sole prerequisite;
it is completed. Rishitha's AI implementation is not a dependency. Her peer
review of this work remains required. C05 #11 and C09 #21 depend on C04;
C05 also depends on S02. Do not unblock them through this research PR.

The revised v2 plan (sections 6, 15, 16, 18; pages 5, 13-15) requires lab-only
access, honest evidence and cross-review. Its Month 3 gate prohibits unknown
live URLs before containment tests pass. Month 2 retains the Microsoft 365
tenant go/no-go; Graph remains experimental/deferred if unavailable.

| Exact Issue #2 acceptance criterion | Evidence and disposition |
| --- | --- |
| Record IMAP/Gmail test-account access and request a Microsoft 365 test tenant | Owner confirms no dedicated accounts/tenant available; access tests BLOCKED. Owner provisioning request recorded below and in the issue evidence comment; no vendor request or tenant provisioning completed. Partial/open. |
| Screenshot an owned synthetic page using a disposable isolated VM with private networks and credentials blocked | BLOCKED. No adequately verified VM. Inert owned fixture prepared; no browser launch, screenshot, network probe or containment test performed. |
| Record sandbox go/no-go and disable uncontrolled navigation; no live remediation | NO-GO recorded. Product has no navigation implementation; none enabled or added. No runtime containment control is claimed. No remediation performed. Peer acceptance pending. |

## Owned test-resource inventory

Inventory is bounded to project documentation, the explicit owner question and
local hypervisor configuration metadata. No personal/employee inbox, saved
browser credentials, token store, guest disk or private network was inspected.
An existing login or Git author address does not establish a dedicated lab account.

| Resource | Verified availability/access | Obstacle and next evidence |
| --- | --- | --- |
| Dedicated Gmail test mailbox | BLOCKED: owner confirms none available; login, API and IMAP not attempted | A dedicated account must become available, with sole lab use and synthetic-only contents attested; exact access needs separate approval. |
| Other dedicated IMAP mailbox | BLOCKED: owner confirms none available | An owned lab server, TLS/auth method and permitted folder must be identified. No guessed endpoints or authentication attempts. |
| Microsoft 365 lab tenant / Exchange Online mailbox | BLOCKED: owner confirms none available | Provisioning request to project owner below remains outstanding. No university/employer/production tenant substitution. |
| Disposable isolated VM | BLOCKED: owner confirms no approved lab VM available | Existing configuration is insufficient; findings below. No guest started or modified. |

### Provider feasibility and permission boundary

These are researched candidate permissions, **not requests for consent**.
No OAuth client, persistent credential, account or mailbox adapter was created.

| Path | Proposed minimum for a later approved lab test | Obstacles and decision |
| --- | --- | --- |
| Gmail API | `https://www.googleapis.com/auth/gmail.metadata` for headers-only inspection; `https://www.googleapis.com/auth/gmail.readonly` only if synthetic body/MIME reading is explicitly approved | Both are restricted scopes and cover the mailbox rather than one chosen message. Metadata cannot supply bodies. Dedicated account, API project, consent/test-user configuration and provider policy review are prerequisites. Prefer API read-only over full-mail IMAP for Gmail; live test NO-GO now. [Google scope reference](https://developers.google.com/workspace/gmail/api/auth/scopes). |
| Gmail IMAP / XOAUTH2 | Provider requires `https://mail.google.com/` | This is broad mail access, including destructive capabilities. Do not request it under this task. No domain-wide delegation or app-password workaround. Gmail IMAP is NO-GO without a separate explicit decision/approval. [Google XOAUTH2](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol). |
| Other IMAP | Provider-specific OAuth scopes, verified TLS; later use `EXAMINE` and bounded `UID FETCH ... BODY.PEEK[]` on an approved synthetic folder | There is no universal IMAP read-only OAuth scope. Client read-only commands do not restrict a broadly privileged token. Server ACLs and dedicated ownership must be established. Avoid flag updates, `STORE`, `COPY`, `MOVE`, `EXPUNGE`, uploads and SMTP. NO-GO while provider/access is unknown. [IMAP specification](https://datatracker.ietf.org/doc/html/rfc9051). |
| Microsoft Graph | Delegated `Mail.ReadBasic` for basic properties; delegated `Mail.Read` only after approval if synthetic body/MIME is needed | Basic access excludes bodies and attachments. Delegated mail access is distinct from application `Mail.Read`, which can read all mailboxes. No application permission, shared-mail access, `Mail.ReadWrite`, `Mail.Send` or tenant-wide consent requested. Tenant policy can still require admin approval. NO-GO pending lab tenant. [Permissions](https://learn.microsoft.com/en-us/graph/permissions-reference), [MIME retrieval](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0). |

Google documents verification requirements for restricted scopes and security
assessment requirements for server storage/transmission; applicable exceptions
and deployment obligations must be reviewed before a connected distribution.
Do not assume lab access establishes production approval. Token expiry, denied
consent and tenant policy are expected failure states, never safety evidence.

### Microsoft 365 provisioning request to the project owner

Requested for C04: provide an owned, separate non-production Microsoft 365 tenant
with an Exchange Online test mailbox containing only invented messages, and an
administrator able to confirm licensing, app-registration policy and approved
delegated scope. Record only availability, owner attestation, lab alias, consent
decision and blockers; keep tenant/account identifiers and credentials out of Git.
No purchase, signup, vendor form, identity verification or consent is authorized
by this request. The owner confirmed no tenant is available; provisioning remains
blocked pending a separately authorized resource decision.

Microsoft's developer sandbox is conditional on eligibility; a production or
education subscription does not prove developer-sandbox entitlement. If ineligible,
record unavailable rather than assuming a free tenant. Do not buy a subscription
without a separate decision. Reassess at the plan's Month 2 tenant gate.
[Official eligibility/setup guidance](https://learn.microsoft.com/en-us/office/developer-program/microsoft-365-developer-program).

### Later mailbox verification protocol (not run)

After ownership verification and separate access approval, use a dedicated lab
account, synthetic message and reviewed OAuth flow. Capture only provider, granted
scope names, sanitized outcome, synthetic fixture hash and revocation outcome.
Never capture tokens, authentication payloads, inbox listings or raw mail logs.
Bound message count/bytes/time; use read-only operations. Verify denied consent,
expired/revoked token, wrong account/tenant, missing scope, inaccessible folder,
TLS failure, timeout and throttling fail closed without retrying into broader
permissions. A list/filter in the client is not server-enforced mailbox isolation.
Stop on unexpected non-synthetic content, redact locally, revoke test access and
record unknown/blocked. No C05 ingestion implementation is included here.

## Sandbox preflight findings

Read-only checks on 2026-11-01 found:

- VMware Workstation `vmrun list`: `Total running VMs: 0`.
- VMware inventory: six registered configuration entries; five configuration files
  exist. All five explicitly configure a present NAT adapter; three also have a
  second private virtual network adapter. These settings do not demonstrate
  blocked host/private/Internet access.
- One VMware configuration lists an enabled shared folder as well as an HGFS
  disable flag; effective sharing was not tested. Clipboard/drag/drop disable
  settings were not established. Missing keys do not prove isolation.
- One VirtualBox VM directory/configuration exists; an enabled NAT adapter is
  configured. The standard VirtualBox executable path is absent. Disposability,
  guest browser state, snapshots, secrets and effective filtering are unverified.
- Hyper-V commands and selected VM services were not returned in this session.
  A CIM hypervisor query was denied; host virtualization state remains unknown.
  WSL availability is not a disposable browser-containment result.

VM names, disk paths, shared-folder paths, MACs and guest identifiers are omitted
from committed evidence. No disks, snapshots or existing guest sessions were
opened. Do not repurpose a coursework or personal VM based on these findings.

**Containment evidence: none.** This is configuration rejection evidence only.
No screenshot, blocked-packet proof, browser version measurement, memory/latency
benchmark or guest destruction result exists. The Compose service is a loopback
synthetic API mock, not a sandbox and not part of this spike.

## Conditional disposable test protocol (not executed)

An owner-designated disposable clone must first have a clean, credential-free
baseline and a verified destruction/revert path. Record guest OS, hypervisor and
browser versions, snapshot/clone identifier (sanitized), date, quotas and reviewer.
No host browser profile, cookies, extensions, tokens, clipboard, drag/drop,
shared folders, USB passthrough or host integration may enter it.

For this local-only C04 spike, require every guest NIC disconnected at the
hypervisor layer, with no NAT, bridged, host-only or private-network route. Verify
the effective configuration and absence of guest routes/resolvers before launch;
do not test by probing the real host, LAN or metadata endpoint. Use an immutable
read-only fixture transfer (for example an ISO), never a host share. If these
conditions cannot be independently verified, stop with `blocked_preflight`.

1. Transfer only [c04-owned.html](../sandbox/fixtures/c04-owned.html), verify its
   SHA-256 and open that single exact local file in a fresh non-root guest browser
   profile. Keep normal browser security enabled. The fixture has no remote
   resources, links, scripts or forms; its CSP is defense in depth, not containment.
2. Use a reviewed navigation allowlist for that exact file; reject other file
   paths, schemes, popups, redirects and downloads. Browser request interception
   alone is not a network boundary. Do not improvise a host browser runner.
3. Capture one synthetic screenshot at 1280x720, bounded to 10 seconds, with a
   bounded output size and one browser job. Record browser launch failure,
   screenshot failure, timeout and quota exhaustion explicitly. Kill the job
   on failure; never fall back to a host browser or unrestricted network.
4. Establish that blocked navigation leaves no new document, no download and
   no emitted traffic using guest-local instrumentation and a disconnected-vNIC
   boundary capture. Evaluate deny decisions without sending traffic to real
   external/private/loopback/metadata destinations. Any unexpected route,
   host integration or outbound traffic is a failed preflight, not a passed test.
5. Verify the screenshot contains only the synthetic marker; sanitize paths and
   window chrome before exporting. Destroy/revert the clone, verify test profile
   and output disposal, and retain only reviewed sanitized evidence outside Git.

| Required case | Current result | Evidence needed to pass later |
| --- | --- | --- |
| Exact local fixture screenshot | NOT RUN: blocked preflight | Fixture hash, synthetic image, versions/config and bounded job outcome |
| External navigation/resource, redirect, popup, download | NOT RUN | Reviewed deny behavior plus zero boundary traffic; no real destinations contacted |
| Host/private/metadata/IPv6 destination | NOT RUN | Policy rejection and disconnected NIC evidence; no private-network probes |
| Credentials, clipboard, sharing, host integration | UNKNOWN: not verified | Clean clone attestation and effective disabled configuration |
| Browser crash, timeout, quota, screenshot failure | NOT RUN | Explicit failure state, terminated job, no host fallback |
| Snapshot revert/destruction | NOT RUN | Disposable clone lifecycle evidence |

This offline protocol does not prove DNS rebinding, redirect-chain filtering,
SSRF resistance or neutral egress for connected browsing. Those remain C09/C10
implementation/security gates. No unknown live URL is permitted by a C04 pass.

## Remaining gates and unrelated tracked gaps

1. A dedicated test mailbox becomes available; owner verifies it and separately
   approves exact access. Current status: blocked, owner confirms none available.
2. Owner answers the Microsoft 365 lab provisioning request; no external
   submission/provisioning is claimed.
3. An approved disposable lab VM becomes available; owner provides a verified
   disposable clone. Complete the local screenshot and
   failure-case evidence under the protocol above, or keep the acceptance blocked.
4. Rishitha reviews this research PR; applicable CI must pass. Leave Issue #2
   open and dependent work gated while mandatory evidence is absent.

C02 QR-decoding deferral remains tracked in #8 / `docs/reports/c02-verification.md`.
C03 PR #101 was merged with a review gap noted in the handoff; check its recorded
review separately rather than treating CI as approval. Neither is a C04 dependency.
S01/S02 and AI work are unchanged. No AI, new product feature, mailbox ingestion,
remediation, deployment or merge is included.
