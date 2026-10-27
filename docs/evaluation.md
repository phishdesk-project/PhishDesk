# Evaluation protocol

Use revised v2 plan section 15. Script synthetic data with invented brands and
lab-only domains, or licensed public data with documented provenance. Start with
at least several hundred labelled messages and meaningful legitimate-but-urgent
coverage. Keep development/calibration sets separate from held-out tests.

Freeze/hash the initial test set by the end of relative Month 2; never tune on it.
Set numeric false-alarm, injection-success and calibration targets only after the
baseline. No values or benchmark results have been invented in this foundation.
Build a fresh final set in Month 7 using new templates, brands and languages; do
not tune on that set before final Month 8 scoring. Prefer time-separated splits.

Compare rules only, classifier only, classifier plus LLM and full pipeline on the
same held-out data. Report precision/recall/F1/confusion matrix, false alarms,
calibration/reliability/Brier score, grounded explanations, brands/clusters and
false associations, injection success by category, latency/resources and cost.
Record model/hardware versions, seeds, configuration, hashes and negative results.

Measure the one-minute verdict goal on the named setup (fast path allowed) and
the ten-minute clean Compose install goal. They are goals, not current claims.
Publish limitations and benchmark provenance; no perfect detection, injection
immunity or error-free remediation promises. Raw/private datasets and models stay
out of Git; commit only approved manifests/licensed safe fixtures.
