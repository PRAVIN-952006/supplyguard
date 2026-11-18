# Verification record

Verified locally on 2026-11-18:

* `pytest`: 7 tests passed.
* `ruff check .`: passed.
* `mypy src`: passed in strict mode.
* CLI smoke tests: valid CycloneDX and SPDX documents passed; missing purl was rejected with a policy error.
* Repository secret scan: no credential/key patterns detected in tracked files.

The initial repository was prepared with a minimal-permission GitHub Actions workflow, but the publishing token did not have the GitHub `workflow` scope. The workflow was therefore retained in the local development history and not uploaded through that token. No CI result is claimed; adding the workflow requires a separately authorized GitHub token with workflow permission.
