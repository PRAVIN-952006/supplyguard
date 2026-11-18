# SupplyGuard

SupplyGuard is an offline quality and policy auditor for CycloneDX and SPDX JSON software bills of materials (SBOMs). It catches incomplete or inconsistent component records before an SBOM is used as supply-chain evidence.

It is intentionally not a vulnerability scanner. Tools such as OWASP Dependency-Check and Trivy answer questions about known vulnerabilities; SupplyGuard checks whether the inventory itself is complete enough to consume reliably. It performs no network access and has no API-key dependency.

## Supported input

The current parser intentionally supports a bounded subset of:

| Format | Accepted versions | Encoding |
| --- | --- | --- |
| CycloneDX | 1.3, 1.4, 1.5, 1.6, 1.7 | JSON |
| SPDX | 2.2, 2.3 | JSON |

This is not full standards conformance. Unsupported versions, malformed JSON, non-object documents, and files over 10 MiB are rejected explicitly. XML, Protobuf, SPDX 3, schema validation, and complete relationship semantics are outside the current release.

## Why it exists

SBOMs are useful only when their component identity and metadata are trustworthy. In practice, generated documents can contain duplicate references, missing versions, absent package URLs, or empty metadata. These defects make later correlation and policy decisions unreliable while remaining easy to miss in a large JSON document.

## Install and use

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
supplyguard tests/fixtures/valid-cyclonedx.json
supplyguard --format json --require-license path/to/sbom.json
```

Exit status is `0` when no error findings exist, `1` when the SBOM fails policy, and `2` for invalid command-line or input data.

Options:

* `--allow-missing-purl` makes package URLs optional.
* `--require-supplier` and `--require-license` add metadata policy checks.
* `--max-missing-version N` allows up to `N` components without versions.
* `--format json` emits machine-readable findings.

## Architecture

```text
JSON file -> bounded loader -> format detector/parser -> normalized components
                                                    -> policy auditor -> text/JSON report
```

The parser normalizes the small common subset needed for quality checks: component reference, name, version, purl, supplier, and license. It also checks that dependency references point to known component references. The auditor applies deterministic rules and never downloads data or executes input-controlled commands.

## Security model

The input SBOM is untrusted data. The loader rejects non-files, invalid UTF-8/JSON, and files larger than 10 MiB by default. Parsing uses the standard-library JSON decoder; no shell, network, dynamic import, or deserialization mechanism is involved. Reports include input-derived component references, so consumers should treat output as untrusted text.

See [the threat model](docs/threat-model.md) for assets, trust boundaries, abuse cases, mitigations, and residual risks.

## Verification

```bash
python -m pytest
```

The project also provides optional developer checks when installed: `ruff check .` and `mypy src`.

## Limitations

SupplyGuard does not resolve dependencies, validate every version of the CycloneDX or SPDX specifications, query vulnerability databases, prove provenance, or determine whether a license is legally compatible. A passing result means the configured quality policy found no errors; it is not a security certification.

## References

* [CISA Software Bill of Materials](https://www.cisa.gov/topics/information-communications-technology-supply-chain-security/sbom)
* [CycloneDX specification](https://cyclonedx.org/specification/overview/)
* [SPDX specification](https://spdx.dev/specifications/)
* [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
