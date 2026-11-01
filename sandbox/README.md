# Dedicated isolated browser service

Lead: Darshan. This directory contains an inert fixture and a handoff boundary; a production browser runner is not implemented. See the v2 plan and [C04 feasibility](../docs/c04-feasibility.md).

The owned synthetic HTML was rendered manually in the disposable offline Ubuntu VM. Terminal evidence reports a 1280x720 headless PNG and successful 10-second job. User-verified WebsiteFilter allows only the owned file and explicitly blocks the five recorded targets. [Evidence and limits](../docs/reports/c04-final-assessment.md) distinguish recovered screenshots from user-attested tests.

No full containment assurance or independent boundary traffic measurement is claimed. Advanced redirects/popups/downloads/subresources, hung-browser cleanup and Firefox-specific quotas remain untested. The Compose mock is not a sandbox. C09/C10 retain the disposable-job and mandatory containment gate; unknown live URLs remain prohibited. No C05 or browser runner implementation was added.
