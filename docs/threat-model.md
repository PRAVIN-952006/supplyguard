# Threat model

## Scope and assets

SupplyGuard consumes a local SBOM supplied by a developer or CI job. The primary assets are the integrity of the audit result, the operator's local environment, and the confidentiality of any metadata embedded in the input or output.

## Trust boundaries

The JSON input crosses into the parser as untrusted data. Command-line arguments and the filesystem are also untrusted. The parser and auditor are trusted application code. No network or external process boundary is crossed.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Oversized input causes resource exhaustion | 10 MiB file-size limit before parsing |
| Malformed JSON crashes or produces a success-shaped result | Explicit decoding and schema-shape errors return exit code 2 |
| Input causes command execution | No subprocess, shell, network, or dynamic evaluation APIs |
| Duplicate references hide ambiguous identity | SG002 is an error |
| Missing identity metadata causes unreliable correlation | PURL, name, and version policy checks |
| Sensitive input is disclosed through logs | No input contents are logged; reports contain only selected component fields |
| Caller mistakes a pass for vulnerability clearance | Documentation explicitly scopes the tool to SBOM quality |

## Abuse cases

An attacker may submit a very large file, deeply nested JSON, invalid encodings, duplicate component references, malformed package URLs, or misleading metadata. The bounded loader, standard JSON parser, deterministic normalization, and explicit findings address these cases. JSON nesting limits are delegated to the runtime parser; deployments processing hostile untrusted files should also enforce a process memory/time limit.

## Residual risks

The tool cannot establish that an SBOM is complete relative to a build, that a purl identifies the intended package, or that a declared license is accurate. It does not authenticate the document or verify provenance. These limitations are intentional and should be addressed by upstream generation, signing, provenance, and independent review.
