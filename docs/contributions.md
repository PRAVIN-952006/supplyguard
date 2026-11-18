# Contribution opportunity assessment

Reviewed 2026-11-18. These are real, active projects and issues. One focused contribution was prepared only after reproducing the issue and adding a regression test.

| Project | Opportunity | Fit | Status and next step |
| --- | --- | --- | --- |
| OpenSSF Scorecard | [#5458](https://github.com/ossf/scorecard/issues/5458), test discovery/fuzzing issue | Strong security/testing fit | Open when reviewed; reproduce locally, understand test conventions, then propose a focused fix |
| OpenSSF Scorecard | [#5451](https://github.com/ossf/scorecard/issues/5451), branch protection bypass data | Strong supply-chain fit | Open proposal; requires Go/GitHub API familiarity and maintainer discussion |
| Anchore Syft | [#5594](https://github.com/anchore/syft/issues/5594), GitHub Actions lockfile dependency support | Strong supply-chain fit | Open feature issue; substantial but aligned with SupplyGuard interests |
| OWASP Dependency-Check | [#8846](https://github.com/dependency-check/DependencyCheck/issues/8846), incomplete advisory retention | Strong security correctness fit | Open issue; requires Java/Maven domain understanding |
| OWASP Dependency-Check | [#8862](https://github.com/dependency-check/DependencyCheck/issues/8862), Scorecard integration | Good security automation fit | Open feature request; evaluate existing architecture before proposing implementation |

Selection criteria were activity, reproducibility, maintainer guidance, scope, and evidence of a genuine engineering improvement. The shortlist is not a claim that any issue is unassigned or guaranteed to accept a contribution; issue status must be rechecked immediately before work.

## Submitted contribution

* [Safety CLI #931](https://github.com/pyupio/safety/pull/931) addresses [issue #921](https://github.com/pyupio/safety/issues/921), where malformed installed distribution metadata could crash pytest configuration. The focused regression test passed. The full suite was also run, but sandbox-dependent network/auth/cache/CLI failures were reported transparently in the PR; merge or acceptance is not claimed.
