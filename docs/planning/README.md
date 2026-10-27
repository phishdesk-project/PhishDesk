# Eight-phase working roadmap

Source: [PhishDesk Revised 8-Month Plan (v2)](PhishDesk-Revised-8-Month-Plan-v2.pdf).
SHA-256: `47b1fafb621f77b094970dcbea90a399274a31455c85828ebddc1827149d584e`. The original blueprint is not needed to override the revised plan.

**No calendar start dates or deadlines.** Month/week numbers describe order at available free-time capacity. All tasks start as planned/backlog.

## Phases and gates

| Relative phase | Milestone | Exit evidence |
| --- | --- | --- |
| M1, W1-4 | v0.0 Foundation | Sandbox and local LLM feasibility recorded; schema-valid synthetic end-to-end exchange; blockers recorded. |
| M2, W5-8 | v0.1 First verdict | Report, parse, classify, explain and reply in the lab; measure the one-minute goal on named hardware/model; freeze the test set; Microsoft 365 go/no-go. |
| M3, W9-12 | v0.2 Sandbox and dashboard | Containment tests pass before any unknown live URL; screenshot/form evidence and validated verdict; protect Week 12 for integration. |
| M4, W13-16 | v0.3 Brands and campaigns | Defensible synthetic clusters; copies found only in authorised mailboxes; corroborated brand signals; mid-project demo. |
| M5, W17-20 | v0.4 Approved response | One provider supports propose, approve, quarantine, audit and restore; zero incorrect removals on the test set. |
| M6, W21-24 | v0.5 Hardening | Mandatory security/contract tests pass; reproducible comparisons; plugin API frozen; protect Week 24 for integration. |
| M7, W25-28 | v0.9 Beta | Outside tester installs, runs the synthetic demo and reports a reproducible issue; fresh final test set; no unsupported claims. |
| M8, W29-32 | v1.0 Launch | Fresh reviewer completes install, analyse, evidence, search, approve, quarantine and restore; security sign-off and reproducible final results. |

## Working rules

96 issues cover 80 core work packages (ten per phase) and 16 scoped newcomer tasks from Month 2 onward. Each issue has one lead and the other owner as reviewer. Task counts are not estimates of equal effort; rebalance at every planning review. Both retain equal ownership.

Use Backlog -> In progress -> In review -> Done. The live issues/project are the progress record; `roadmap.json` is a source/acceptance baseline, not a live status export. Milestone open/closed counts show release progress. Close only after verified deliverables/cross-review, never because a scaffold exists.

The [Roadmap tab](https://github.com/orgs/phishdesk-project/projects/1/views/2) uses a milestone-grouped table because native timeline bars require calendar dates. Keep calendar fields blank. Filter by assignee for personal work; labels show phase/track. Native dependency links plus body references show prerequisites.

## Cut list, in order

1. Stretch experiment (only considered after v0.5).
2. Second remediation provider (experimental).
3. Campaign explanation polish.
4. Graph connector (experimental/deferred after tenant gate).
5. Number of reference brands.
6. Dashboard polish.

Never cut containment, approval controls, privacy/redaction, contracts/tests or honest benchmark reporting. If more than one relative working week behind a gate, agree cuts before adding scope. Protect relative Weeks 12 and 24.

## Handoffs and reports

Week 1: agree the contracts and ownership decisions. By relative Week 5: Darshan publishes the API/OpenAPI/mocks so Rishitha can build React in parallel. AI hands over fixtures, model cards and reproducible results. A report chapter accompanies each phase; Month 8 finalises the report.

From Month 2, plan about 2-3 community hours per owner per working week and a 48-hour reply target. Meeting cadence adapts to free time; preserve runnable demos and monthly gate reviews. Visibility changes, invitations, launch posts and external outreach require explicit owner action.

## Setup audit and access limits

Initial main at `9837c27a2feef99f6cdf3d43583deb094e7604eb` contained README, Apache-2.0 LICENSE, Python .gitignore and valid dual-team CODEOWNERS; no application, issues, CI or releases. Eight undated milestones, fifteen labels and an empty four-stage project already existed. Those assets were reused, not replaced.

The connector could not access this private repository; existing Git authentication could. That credential has repo/workflow scopes but no Project API scope, so project changes use the signed-in UI. No credential is saved in the repository. GitHub reports private-plan restrictions for rulesets/branch protection/CODEOWNERS enforcement. Cross-review remains manual. CodeQL is conditionally configured only where supported. No security access or repository visibility is changed.

## Source index

| Key | Relative phase | Lead | Deliverable | Dependencies |
| --- | --- | --- | --- | --- |
| [C01 #1](https://github.com/phishdesk-project/PhishDesk/issues/1) | M1 | k-Darshan-chowdary | Bootstrap FastAPI, logging, CI and Compose | None |
| [C02 #8](https://github.com/phishdesk-project/PhishDesk/issues/8) | M1 | k-Darshan-chowdary | Implement a bounded defensive MIME parser | S02, C01 |
| [C03 #9](https://github.com/phishdesk-project/PhishDesk/issues/9) | M1 | k-Darshan-chowdary | Add deterministic sender and URL checks | [C02 #8](https://github.com/phishdesk-project/PhishDesk/issues/8) |
| [C04 #2](https://github.com/phishdesk-project/PhishDesk/issues/2) | M1 | k-Darshan-chowdary | Run mailbox-access and sandbox feasibility spikes | [C01 #1](https://github.com/phishdesk-project/PhishDesk/issues/1) |
| [A01 #3](https://github.com/phishdesk-project/PhishDesk/issues/3) | M1 | RishithaDama | Design labelled data and scripted synthetic corpus | None |
| [A02 #4](https://github.com/phishdesk-project/PhishDesk/issues/4) | M1 | RishithaDama | Train reproducible TF-IDF logistic baseline | [A01 #3](https://github.com/phishdesk-project/PhishDesk/issues/3) |
| [A03 #5](https://github.com/phishdesk-project/PhishDesk/issues/5) | M1 | RishithaDama | Measure local LLM feasibility and fallback | [A01 #3](https://github.com/phishdesk-project/PhishDesk/issues/3) |
| [A04 #10](https://github.com/phishdesk-project/PhishDesk/issues/10) | M1 | RishithaDama | Build a fake analyser and contract integration fixtures | [S02 #7](https://github.com/phishdesk-project/PhishDesk/issues/7) |
| [S01 #6](https://github.com/phishdesk-project/PhishDesk/issues/6) | M1 | k-Darshan-chowdary | Record equal ownership, decisions and Month 1 gate | None |
| [S02 #7](https://github.com/phishdesk-project/PhishDesk/issues/7) | M1 | RishithaDama | Agree Evidence, Verdict and ActionRequest v1 | None |
| [C05 #11](https://github.com/phishdesk-project/PhishDesk/issues/11) | M2 | k-Darshan-chowdary | Implement IMAP and Gmail ingest adapters | C04, S02 |
| [C06 #12](https://github.com/phishdesk-project/PhishDesk/issues/12) | M2 | k-Darshan-chowdary | Persist cases and run idempotent async jobs | C01, C02 |
| [C07 #13](https://github.com/phishdesk-project/PhishDesk/issues/13) | M2 | k-Darshan-chowdary | Publish case API and mock API by relative Week 5 | [S02 #7](https://github.com/phishdesk-project/PhishDesk/issues/7) |
| [C08 #14](https://github.com/phishdesk-project/PhishDesk/issues/14) | M2 | k-Darshan-chowdary | Add retention, redaction, delete-case and tenant gate | C06, C07 |
| [A05 #15](https://github.com/phishdesk-project/PhishDesk/issues/15) | M2 | RishithaDama | Extract structured intent grounded in evidence | A03, S02 |
| [A06 #16](https://github.com/phishdesk-project/PhishDesk/issues/16) | M2 | RishithaDama | Fuse deterministic and model risk safely | C03, A02, A05 |
| [A07 #17](https://github.com/phishdesk-project/PhishDesk/issues/17) | M2 | RishithaDama | Freeze test data and add injection starter regression | A01, A02, A05 |
| [A08 #18](https://github.com/phishdesk-project/PhishDesk/issues/18) | M2 | RishithaDama | Scaffold React against mocks and show a first-verdict demo | C07, A04, A06 |
| [S03 #19](https://github.com/phishdesk-project/PhishDesk/issues/19) | M2 | k-Darshan-chowdary | Verify v0.1 quick start and write report chapter 2 | C05, C06, C07, C08, A06, A07, A08 |
| [S04 #20](https://github.com/phishdesk-project/PhishDesk/issues/20) | M2 | RishithaDama | Prepare community soft-launch package | [A08 #18](https://github.com/phishdesk-project/PhishDesk/issues/18) |
| [C09 #21](https://github.com/phishdesk-project/PhishDesk/issues/21) | M3 | k-Darshan-chowdary | Build disposable browser evidence jobs | C04, C06 |
| [C10 #22](https://github.com/phishdesk-project/PhishDesk/issues/22) | M3 | k-Darshan-chowdary | Prove sandbox containment and neutral egress | [C09 #21](https://github.com/phishdesk-project/PhishDesk/issues/21) |
| [C11 #23](https://github.com/phishdesk-project/PhishDesk/issues/23) | M3 | k-Darshan-chowdary | Expose authenticated evidence and screenshot references | C07, C09 |
| [C12 #24](https://github.com/phishdesk-project/PhishDesk/issues/24) | M3 | k-Darshan-chowdary | Publish check plugin example and boundary tests | C03, S02 |
| [A09 #25](https://github.com/phishdesk-project/PhishDesk/issues/25) | M3 | RishithaDama | Separate hostile input and validate LLM behaviour | A05, A07 |
| [A10 #26](https://github.com/phishdesk-project/PhishDesk/issues/26) | M3 | RishithaDama | Expand injection suite across content channels | [A09 #25](https://github.com/phishdesk-project/PhishDesk/issues/25) |
| [A11 #27](https://github.com/phishdesk-project/PhishDesk/issues/27) | M3 | RishithaDama | Ground page analysis in sandbox evidence | C09, A09 |
| [A12 #28](https://github.com/phishdesk-project/PhishDesk/issues/28) | M3 | RishithaDama | Deliver dashboard v1 evidence and verdict screens | A08, C11, A11 |
| [S05 #29](https://github.com/phishdesk-project/PhishDesk/issues/29) | M3 | k-Darshan-chowdary | Protect Week 12 integration and run v0.2 containment gate | C10, C11, A10, A12 |
| [S06 #30](https://github.com/phishdesk-project/PhishDesk/issues/30) | M3 | RishithaDama | Create docs skeleton and report chapter 3 | C12, A12 |
| [C13 #31](https://github.com/phishdesk-project/PhishDesk/issues/31) | M4 | k-Darshan-chowdary | Add experimental Graph read/search connector | C08, C05 |
| [C14 #32](https://github.com/phishdesk-project/PhishDesk/issues/32) | M4 | k-Darshan-chowdary | Extract infrastructure features and graph edges | C03, C09 |
| [C15 #33](https://github.com/phishdesk-project/PhishDesk/issues/33) | M4 | k-Darshan-chowdary | Search related copies within authorised mailboxes | C05, C14 |
| [C16 #37](https://github.com/phishdesk-project/PhishDesk/issues/37) | M4 | k-Darshan-chowdary | Expose campaign API and membership evidence | C15, A15 |
| [A13 #34](https://github.com/phishdesk-project/PhishDesk/issues/34) | M4 | RishithaDama | Curate a small approved brand reference corpus | [A01 #3](https://github.com/phishdesk-project/PhishDesk/issues/3) |
| [A14 #35](https://github.com/phishdesk-project/PhishDesk/issues/35) | M4 | RishithaDama | Implement visual matching with domain corroboration | A13, C09 |
| [A15 #36](https://github.com/phishdesk-project/PhishDesk/issues/36) | M4 | RishithaDama | Version embeddings and explain campaign clusters | C14, A02 |
| [A16 #38](https://github.com/phishdesk-project/PhishDesk/issues/38) | M4 | RishithaDama | Build campaign view and evaluate brands/clusters | A12, A14, A15, C16 |
| [S07 #39](https://github.com/phishdesk-project/PhishDesk/issues/39) | M4 | k-Darshan-chowdary | Run v0.3 authorised-copy and mid-project demo gate | C13, C15, C16, A16 |
| [S08 #40](https://github.com/phishdesk-project/PhishDesk/issues/40) | M4 | RishithaDama | Publish brand guide, demo rehearsal and report chapter 4 | A13, A16 |
| [C17 #41](https://github.com/phishdesk-project/PhishDesk/issues/41) | M5 | k-Darshan-chowdary | Validate scoped proposals and dry-run policy | S02, C15 |
| [C18 #42](https://github.com/phishdesk-project/PhishDesk/issues/42) | M5 | k-Darshan-chowdary | Implement role approvals and revalidate before execution | [C17 #41](https://github.com/phishdesk-project/PhishDesk/issues/41) |
| [C19 #43](https://github.com/phishdesk-project/PhishDesk/issues/43) | M5 | k-Darshan-chowdary | Implement quarantine and restore for one provider | [C18 #42](https://github.com/phishdesk-project/PhishDesk/issues/42) |
| [C20 #44](https://github.com/phishdesk-project/PhishDesk/issues/44) | M5 | k-Darshan-chowdary | Record redacted action audit and restoration history | C18, C19 |
| [A17 #45](https://github.com/phishdesk-project/PhishDesk/issues/45) | M5 | RishithaDama | Calibrate confidence by category and missing evidence | A07, A06 |
| [A18 #46](https://github.com/phishdesk-project/PhishDesk/issues/46) | M5 | RishithaDama | Add advisory triage priority to fused verdicts | A17, A06 |
| [A19 #47](https://github.com/phishdesk-project/PhishDesk/issues/47) | M5 | RishithaDama | Publish benchmark v1 and failure analysis | A10, A14, A15, A17 |
| [A20 #48](https://github.com/phishdesk-project/PhishDesk/issues/48) | M5 | RishithaDama | Build approval queue, scope preview and restore UI | A12, C18, C19, C20 |
| [S09 #49](https://github.com/phishdesk-project/PhishDesk/issues/49) | M5 | k-Darshan-chowdary | Verify v0.4 response chain and zero incorrect removals | C20, A20, A19 |
| [S10 #50](https://github.com/phishdesk-project/PhishDesk/issues/50) | M5 | RishithaDama | Write report chapter 5 and benchmark announcement draft | A19, S09 |
| [C21 #51](https://github.com/phishdesk-project/PhishDesk/issues/51) | M6 | k-Darshan-chowdary | Run threat-model security regression and fuzzing | C10, C20 |
| [C22 #52](https://github.com/phishdesk-project/PhishDesk/issues/52) | M6 | k-Darshan-chowdary | Freeze documented plugin API and permissions | C12, C21 |
| [C23 #53](https://github.com/phishdesk-project/PhishDesk/issues/53) | M6 | k-Darshan-chowdary | Add security CI, dependency and image review | C01, C21 |
| [C24 #54](https://github.com/phishdesk-project/PhishDesk/issues/54) | M6 | k-Darshan-chowdary | Document deployment, backup, restore and upgrades | C08, C21 |
| [A21 #55](https://github.com/phishdesk-project/PhishDesk/issues/55) | M6 | RishithaDama | Run same-data ablations | [A19 #47](https://github.com/phishdesk-project/PhishDesk/issues/47) |
| [A22 #56](https://github.com/phishdesk-project/PhishDesk/issues/56) | M6 | RishithaDama | Compare local and optional cloud models | [A21 #55](https://github.com/phishdesk-project/PhishDesk/issues/55) |
| [A23 #57](https://github.com/phishdesk-project/PhishDesk/issues/57) | M6 | RishithaDama | Evaluate robustness and explanation feedback | A21, A10 |
| [A24 #58](https://github.com/phishdesk-project/PhishDesk/issues/58) | M6 | RishithaDama | Publish plugin tutorial and live docs content | C22, S06 |
| [S11 #59](https://github.com/phishdesk-project/PhishDesk/issues/59) | M6 | k-Darshan-chowdary | Protect Week 24 buffer and run v0.5 gate | C21, C22, C23, C24, A21, A23, A24 |
| [S12 #60](https://github.com/phishdesk-project/PhishDesk/issues/60) | M6 | RishithaDama | Write evaluation draft chapter 6 and community tutorial | A21, A22, A23, A24 |
| [C25 #61](https://github.com/phishdesk-project/PhishDesk/issues/61) | M7 | k-Darshan-chowdary | Test worker recovery, retention and operational reliability | C24, C06 |
| [C26 #62](https://github.com/phishdesk-project/PhishDesk/issues/62) | M7 | k-Darshan-chowdary | Document one-instance-per-client operations | [C24 #54](https://github.com/phishdesk-project/PhishDesk/issues/54) |
| [C27 #63](https://github.com/phishdesk-project/PhishDesk/issues/63) | M7 | k-Darshan-chowdary | Prepare beta install, vulnerability and tester onboarding | C25, C26 |
| [C28 #68](https://github.com/phishdesk-project/PhishDesk/issues/68) | M7 | k-Darshan-chowdary | Fix beta security and reliability blockers | C27, A28 |
| [A25 #64](https://github.com/phishdesk-project/PhishDesk/issues/64) | M7 | RishithaDama | Build untouched fresh final evaluation set | A07, A23 |
| [A26 #65](https://github.com/phishdesk-project/PhishDesk/issues/65) | M7 | RishithaDama | Stress-test injections, brands, clusters and uncertainty | A25, A23 |
| [A27 #66](https://github.com/phishdesk-project/PhishDesk/issues/66) | M7 | RishithaDama | Tune inference and dashboard from beta feedback | A24, A23 |
| [A28 #67](https://github.com/phishdesk-project/PhishDesk/issues/67) | M7 | RishithaDama | Analyse outside tester feedback and reproduce issues | C27, A27 |
| [S13 #69](https://github.com/phishdesk-project/PhishDesk/issues/69) | M7 | k-Darshan-chowdary | Run v0.9 beta readiness and defect gate | C28, A25, A26, A28 |
| [S14 #70](https://github.com/phishdesk-project/PhishDesk/issues/70) | M7 | RishithaDama | Write chapter 7, beta and injection-post drafts | A26, A28 |
| [C29 #71](https://github.com/phishdesk-project/PhishDesk/issues/71) | M8 | k-Darshan-chowdary | Run final security regression and remove unsupported claims | C28, S13 |
| [C30 #72](https://github.com/phishdesk-project/PhishDesk/issues/72) | M8 | k-Darshan-chowdary | Prepare release candidate, changelog and deployment matrix | C29, C24 |
| [C31 #73](https://github.com/phishdesk-project/PhishDesk/issues/73) | M8 | k-Darshan-chowdary | Complete provider, privacy and responsible-use operations docs | C30, C08 |
| [C32 #78](https://github.com/phishdesk-project/PhishDesk/issues/78) | M8 | k-Darshan-chowdary | Rehearse owned-account full demo and restoration | C29, C30, A32 |
| [A29 #74](https://github.com/phishdesk-project/PhishDesk/issues/74) | M8 | RishithaDama | Run final benchmark on the fresh frozen set | A25, A26, C29 |
| [A30 #75](https://github.com/phishdesk-project/PhishDesk/issues/75) | M8 | RishithaDama | Complete methods report and model documentation | A29, A21, A22 |
| [A31 #76](https://github.com/phishdesk-project/PhishDesk/issues/76) | M8 | RishithaDama | Prepare final presentation and reproducible results | [A30 #75](https://github.com/phishdesk-project/PhishDesk/issues/75) |
| [A32 #77](https://github.com/phishdesk-project/PhishDesk/issues/77) | M8 | RishithaDama | Polish final demo evidence and dashboard explanations | A27, A29, A20 |
| [S15 #79](https://github.com/phishdesk-project/PhishDesk/issues/79) | M8 | k-Darshan-chowdary | Complete v1.0 security sign-off and fresh-reviewer gate | C31, C32, A29, A30, A32 |
| [S16 #80](https://github.com/phishdesk-project/PhishDesk/issues/80) | M8 | RishithaDama | Finalise report and prepare post-release launch kit | S15, A31 |
| [G01 #81](https://github.com/phishdesk-project/PhishDesk/issues/81) | M2 | k-Darshan-chowdary | Add synthetic malformed MIME fixture | [C02 #8](https://github.com/phishdesk-project/PhishDesk/issues/8) |
| [G02 #82](https://github.com/phishdesk-project/PhishDesk/issues/82) | M2 | RishithaDama | Add legitimate-but-urgent synthetic message | [A01 #3](https://github.com/phishdesk-project/PhishDesk/issues/3) |
| [G03 #83](https://github.com/phishdesk-project/PhishDesk/issues/83) | M2 | k-Darshan-chowdary | Document IMAP provider error example | [C05 #11](https://github.com/phishdesk-project/PhishDesk/issues/11) |
| [G04 #84](https://github.com/phishdesk-project/PhishDesk/issues/84) | M2 | RishithaDama | Add accessible mock dashboard empty state | [A08 #18](https://github.com/phishdesk-project/PhishDesk/issues/18) |
| [G05 #85](https://github.com/phishdesk-project/PhishDesk/issues/85) | M2 | k-Darshan-chowdary | Explain unknown domain-age lookup | [C03 #9](https://github.com/phishdesk-project/PhishDesk/issues/9) |
| [G06 #86](https://github.com/phishdesk-project/PhishDesk/issues/86) | M2 | RishithaDama | Add one injection starter fixture | [A07 #17](https://github.com/phishdesk-project/PhishDesk/issues/17) |
| [G07 #87](https://github.com/phishdesk-project/PhishDesk/issues/87) | M3 | k-Darshan-chowdary | Document screenshot timeout example | [C11 #23](https://github.com/phishdesk-project/PhishDesk/issues/23) |
| [G08 #88](https://github.com/phishdesk-project/PhishDesk/issues/88) | M3 | RishithaDama | Improve case reason accessibility | [A12 #28](https://github.com/phishdesk-project/PhishDesk/issues/28) |
| [G09 #89](https://github.com/phishdesk-project/PhishDesk/issues/89) | M3 | k-Darshan-chowdary | Add check-plugin tutorial fixture | [C12 #24](https://github.com/phishdesk-project/PhishDesk/issues/24) |
| [G10 #90](https://github.com/phishdesk-project/PhishDesk/issues/90) | M4 | RishithaDama | Document a data-only invented brand template | [A13 #34](https://github.com/phishdesk-project/PhishDesk/issues/34) |
| [G11 #91](https://github.com/phishdesk-project/PhishDesk/issues/91) | M4 | k-Darshan-chowdary | Write authorised mailbox scope example | [C15 #33](https://github.com/phishdesk-project/PhishDesk/issues/33) |
| [G12 #92](https://github.com/phishdesk-project/PhishDesk/issues/92) | M2 | RishithaDama | Add confusion-matrix explanation | [A02 #4](https://github.com/phishdesk-project/PhishDesk/issues/4) |
| [G13 #93](https://github.com/phishdesk-project/PhishDesk/issues/93) | M5 | k-Darshan-chowdary | Document redacted audit example | [C20 #44](https://github.com/phishdesk-project/PhishDesk/issues/44) |
| [G14 #94](https://github.com/phishdesk-project/PhishDesk/issues/94) | M5 | RishithaDama | Document reliability-plot interpretation | [A17 #45](https://github.com/phishdesk-project/PhishDesk/issues/45) |
| [G15 #95](https://github.com/phishdesk-project/PhishDesk/issues/95) | M6 | k-Darshan-chowdary | Improve clean-install troubleshooting | [C24 #54](https://github.com/phishdesk-project/PhishDesk/issues/54) |
| [G16 #96](https://github.com/phishdesk-project/PhishDesk/issues/96) | M6 | RishithaDama | Add benchmark limitations glossary | [A21 #55](https://github.com/phishdesk-project/PhishDesk/issues/55) |
