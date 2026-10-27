# Security regression track

Current boundary tests are in `tests/contract/test_v1.py`: invalid model output,
mismatched identity/references, risk-floor downgrade, missing uncertainty and
unapproved/wildcard action proposals. Broader parser, injection, SSRF, sandbox,
permissions and remediation tests are planned issues; none are claimed complete.
