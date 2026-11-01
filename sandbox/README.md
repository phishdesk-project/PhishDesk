# Dedicated isolated browser service

Lead: Darshan. Planned work; this directory is a handoff boundary, not an implemented feature.
See the issue roadmap and v2 plan. Use synthetic/licensed data and cross-review.

[C04 feasibility decision and conditional test protocol](../docs/c04-feasibility.md):
NO-GO pending a verified disposable isolated VM. The local synthetic HTML fixture
is prepared but has not been opened or screenshotted in a guest. No browser runner,
network boundary or containment test is implemented here. The Compose mock is not
a sandbox. Keep navigation unavailable until the required gates pass.
