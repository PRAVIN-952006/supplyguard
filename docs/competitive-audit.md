# Competitive audit

Reviewed 2026-11-18 from public primary repositories and documentation. This is an overlap analysis, not a novelty claim.

## Capability comparison

| Tool | Primary role | Formats / scope | Validation or quality | Workflow depth | Evidence |
| --- | --- | --- | --- | --- | --- |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | BOM manipulation | CycloneDX JSON/XML/Protobuf/CSV and SPDX JSON 2.3 | Schema validation, diff, merge, analyze | Mature CLI, signing and verification, pinned releases | Source tree has dedicated `Validate`, `Diff`, `Merge`, `Sign`, and `Verify` commands; 0.33.1 released 2026-07-23 |
| [CycloneDX sbom-utility](https://github.com/CycloneDX/sbom-utility) | BOM API/query/edit platform | CycloneDX 1.2–1.7 and SPDX 2.1–2.3 | Official versioned schemas plus custom JSON validation | Query, reports, trim, patch, diff, server mode, extensive tests | README and `cmd/*_test.go`; v0.19.2 released 2026-06-25 |
| [Interlynk sbomqs](https://github.com/interlynk-io/sbomqs) | Quality/compliance scoring | SPDX/CycloneDX and policy/compliance profiles | Weighted 0–10 scoring, NTIA/BSI/FSCT and other profiles | JSON score output, CI threshold examples, compliance workflows | README, `pkg/compliance`, `pkg/engine`, and v2.1.3 release 2026-10-14 |
| [eBay sbom-scorecard](https://github.com/eBay/sbom-scorecard) | SBOM quality score | SPDX, CycloneDX, Syft | Weighted spec/generation/package completeness score | Small CLI and reports; repository labels itself WIP | README and `pkg/{cdx,spdx}`; last release 0.0.7 in 2023 |
| [SPDX tools-python](https://github.com/spdx/tools-python) | SPDX library | Tag/Value, RDF, JSON, YAML, XML; SPDX 2.2/2.3 with v3 work | Full SPDX validation, parse/convert/create | Library/CLI, cross-platform CI, 0.8.5 release | README and package tests; v0.8.5 released 2026-03-13 |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Repository security posture | GitHub-hosted repositories and dependency risk | Heuristic checks scored 0–10, structured results | BigQuery data, CI action, SLSA-backed releases | README, `docs/checks.md`, v5.6.0 released 2026-10-12 |
| [Syft](https://github.com/anchore/syft) | SBOM generation | Images, filesystems, archives, many ecosystems | Generation fidelity rather than quality scoring | Go library/CLI, multiple formats, attestations | README and validations workflow; v1.57.2 released 2026-11-16 |
| [Trivy](https://github.com/aquasecurity/trivy) | Broad security scanning | Containers, repos, clouds, Kubernetes, SBOM inputs | Vulnerabilities, licenses, misconfigurations, secrets | Mature scanner and CI integrations | README and SBOM guide; v0.76.2 released 2026-11-05 |
| **SupplyGuard 0.1.0** | Small local policy audit prototype | Limited CycloneDX/SPDX JSON subset | Deterministic checks for purl, name, version, refs, metadata | Python CLI, text/JSON output, no network | This repository, 2026-11-18 |

## Assessment

SupplyGuard does not currently have a defensible flagship position. Its current checks are useful as a learning implementation, but they overlap with schema validation, quality scoring, and metadata checks already provided by the tools above. Its parser is intentionally incomplete: it does not support XML, full schema versions, relationship/reference integrity, or standards-complete validation.

**Decision: C — retain as an initial learning project while researching a stronger flagship.** The repository and v0.1.0 history remain intact. SupplyGuard may receive correctness improvements that make its limitations explicit, but no new release should be published until a materially differentiated scope is demonstrated with tests and comparison evidence.

## Defensible future direction if retained

The only promising direction is not “another SBOM scorer.” A future version would need to become a reproducible developer workflow gate focused on:

1. standards-backed parsing delegated to established libraries or validators;
2. baseline-to-baseline regression policy with explainable component identity and dependency-reference changes;
3. stable machine-readable findings for CI/SARIF;
4. an explicit policy profile format with deterministic exit semantics; and
5. benchmark fixtures showing false-positive and false-negative behavior against real generated SBOMs.

These are hypotheses for further investigation, not claims that the gap is currently unique.
