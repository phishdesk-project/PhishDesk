# C04 research verification - 2026-11-01

Issue: [C04 #2](https://github.com/phishdesk-project/PhishDesk/issues/2).
Decision and conditional protocols: [c04-feasibility.md](../c04-feasibility.md).
Peer reviewer: RishithaDama. Mandatory runtime evidence is blocked; issue stays open.

## Repository and source verification

- Existing Windows checkout was clean on `feature/cyber-c03-deterministic-checks`.
  Fetched origin, fast-forwarded local main, then created
  `feature/cyber-c04-feasibility` from
  `c639cfc6da91422dcd76009c247ba93271dea651`. No reset, stash, source deletion,
  dependency change or modification of other work was needed.
- The GitHub connector returned 404 for the private repository. Existing Git
  authentication and the signed-in GitHub browser tab were used instead.
  No credential was printed or copied into an artifact.
- Live Issue #2's acceptance criteria match the checked-in roadmap. Native
  relationships show completed C01 as the only prerequisite; C05 and C09 are
  downstream. No Rishitha AI implementation dependency was found.
- The 15-page v2 PDF was checked at its relevant sections 6, 15, 16 and 18 and
  associated Month 3 safety gate. SHA-256 matches the roadmap source:
  `47b1fafb621f77b094970dcbea90a399274a31455c85828ebddc1827149d584e`.
- Live PR #101 is merged; the reviewer panel still reports awaiting requested
  review from RishithaDama. C02 QR deferral remains tracked separately in #8.

## Preflight commands and observed results

Only configuration metadata was inspected. VM identities, disk paths, shared
paths and other private identifiers are intentionally absent from this report.

| Check | Observed outcome |
| --- | --- |
| `git status --porcelain=v1`, fetch, fast-forward, branch creation | Initial tree clean; base SHA above; C04 branch created |
| VMware Workstation `vmrun list` | `Total running VMs: 0` |
| Parse VMware `inventory.vmls` config references; inspect only network/isolation keys in existing `.vmx` files | 6 registered entries; 5 existing configs; all 5 have present NAT; 3 also have private virtual-network adapters; 1 lists an enabled share and HGFS-disable setting. Effective isolation unknown. |
| Parse existing VirtualBox `.vbox` adapter settings | One configuration with enabled NAT; standard `VBoxManage.exe` location absent. No guest launched. |
| `Get-Command` for Hyper-V, VirtualBox, VMware, Docker and WSL commands; selected VM services | WSL command returned; other probed commands/services not returned. VMware executable found separately at its installed path. This is a bounded inventory, not proof that no other hypervisor exists. |
| `Get-CimInstance Win32_ComputerSystem` | Access denied; hypervisor status unknown. No system settings changed. |
| Project document search and explicit owner inventory question | No dedicated mailbox or M365 lab tenant verified. No provider connection, registration, consent or credential inspection. Owner provisioning request recorded; external request not submitted. |

No guest disk or saved inbox was read. No VM snapshot was changed. No private
endpoint, metadata service, Internet test target or suspicious live site was
contacted. Vendor documentation and GitHub access are research/repository traffic,
not guest containment testing. No raw browser sandbox capture exists.

## Local validation

Existing `.venv`, Windows Python 3.13.1. Only docs and an inert HTML fixture change.
No permanent tests that duplicate documentation or implement a browser runner
were added. The existing regression suite remains unchanged.

| Command/check | Result |
| --- | --- |
| `python -m ruff check src tests scripts` | All checks passed! |
| `python -m ruff format --check src tests scripts` | 30 files already formatted |
| `python -m mypy` | Success: no issues found in 12 source files |
| `python -m pytest -q --basetemp=.pytest_cache/c04-final` | 193 passed, 1 warning in 20.74s; exit 0. Existing Starlette/httpx deprecation warning. |
| `python scripts/export_contracts.py --check` | Exit 0; no schema/fixture/OpenAPI drift |
| `python scripts/check_roadmap.py` | 96 undated tasks; all eight phases; cross-review and dependency graph valid |
| `python -m pip check` | No broken requirements found. |
| `python -m pip_audit --disable-pip --no-deps -r requirements.lock` | No known vulnerabilities found; exit 0. Uses the fully pinned runtime lock. Audit warns that dependency hashes are recommended. |
| Local Markdown link resolution and HTML static inspection | All relative links resolve; fixture has the synthetic marker and no script, form, iframe, image, link, object, embed, anchor, base, resource URL or event-handler attribute. No browser execution. |
| `git diff --check` | Passed |

The first restricted pytest run stalled and was interrupted; C03 documents the
same Windows subprocess limitation. Final run uses normal process access and
explicit cache temp directory. The first default pip-audit invocation failed
during temporary pip setup; the explicit pinned-lock audit above completed with
network access. Neither attempt changed tracked requirements.

Fixture SHA-256 (exact committed bytes):
`2f60343647ac98d09f8982b9db459a941d5937fdc8786ed5a07f99315239a831`.
The fixture has **not** been opened in a VM or screenshotted. CSP and static
inspection do not demonstrate containment.

## Acceptance limits

Connected mailbox positive/negative tests: **NOT RUN**. Tenant access:
**UNVERIFIED**. Local guest screenshot, navigation rejection, private-network
blocking, credentials isolation, crash/timeout and destruction tests: **NOT RUN**.
Containment: **NOT ACHIEVED / NOT CLAIMED**. Preserve unknown/blocked states.

Submit this bounded research evidence for cross-review; keep #2 open and its
downstream gates intact. Approval of this document is not completion of the
missing screenshot acceptance criterion. No merge or live navigation is authorized.
