# Project selection research

This decision record compares five feasible directions. Scores are deliberately qualitative and reflect a student-maintainable, local-first project rather than a claim that any problem is unsolved.

| Direction | Usefulness | Depth | Differentiation opportunity | Feasibility | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| SBOM quality/policy auditing | High | High | High | High | Selected |
| Vulnerability lookup/SCA | High | High | Low | Medium | Existing tools are mature |
| Secrets detection | High | Medium | Low | High | Many mature scanners |
| Privacy data-flow checks | High | High | Medium | Low | Broad language/runtime scope |
| Defensive incident automation | High | High | Medium | Medium | Needs integrations and operational data |

## Evidence and gap

* CISA describes SBOMs as a building block for software security and supply-chain risk management and highlights VEX as a related consumer workflow: <https://www.cisa.gov/topics/information-communications-technology-supply-chain-security/sbom> (accessed 2026-11-18).
* OWASP Dependency-Check is a mature SCA suite that identifies dependencies and checks publicly disclosed vulnerabilities: <https://owasp.org/www-project-dependency-check/> (accessed 2026-11-18).
* CycloneDX and SPDX provide interoperable SBOM specifications: <https://cyclonedx.org/specification/overview/> and <https://spdx.dev/specifications/> (accessed 2026-11-18).
* The existing SCA tools demonstrate that vulnerability lookup is a crowded direction. A smaller, defensible gap is deterministic validation of the inventory before vulnerability correlation or policy decisions.

## Selection rationale

SupplyGuard was selected because it can be useful without paid services, API keys, or network access; it exercises parsing, data modeling, policy design, secure input handling, testing, and CLI ergonomics; and its limitations can be stated precisely. It is not presented as a replacement for SCA, provenance, signing, or legal license review.
