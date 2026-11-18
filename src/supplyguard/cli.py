from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import Policy, audit
from .parsers import SBOMParseError, load_document, parse_components


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supplyguard",
        description="Audit CycloneDX or SPDX JSON SBOM quality without network access.",
    )
    parser.add_argument("input", type=Path, help="path to a CycloneDX or SPDX JSON document")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--allow-missing-purl", action="store_true")
    parser.add_argument("--require-supplier", action="store_true")
    parser.add_argument("--require-license", action="store_true")
    parser.add_argument("--max-missing-version", type=int, default=0, metavar="N")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_missing_version < 0:
        print("--max-missing-version must be non-negative", file=sys.stderr)
        return 2
    try:
        document = load_document(args.input)
        format_name, components, metadata = parse_components(document, str(args.input))
        result = audit(
            format_name,
            components,
            metadata,
            Policy(
                require_purl=not args.allow_missing_purl,
                require_supplier=args.require_supplier,
                require_license=args.require_license,
                max_components_without_version=args.max_missing_version,
            ),
        )
    except SBOMParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        print(f"format: {result.format}")
        print(f"components: {result.counts['components']}")
        print(f"status: {'PASS' if result.passed else 'FAIL'}")
        for finding in result.findings:
            suffix = f" [{finding.component_ref}]" if finding.component_ref else ""
            print(f"{finding.severity.upper()} {finding.rule_id}{suffix}: {finding.message}")
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
