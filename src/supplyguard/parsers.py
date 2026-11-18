from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Component


class SBOMParseError(ValueError):
    """Raised when an input is not a supported JSON SBOM."""


def load_document(path: Path, max_bytes: int = 10 * 1024 * 1024) -> dict[str, Any]:
    if not path.is_file():
        raise SBOMParseError(f"input is not a regular file: {path}")
    if path.stat().st_size > max_bytes:
        raise SBOMParseError(f"input exceeds the {max_bytes} byte safety limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SBOMParseError(f"could not read valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SBOMParseError("top-level JSON value must be an object")
    return document


def detect_format(document: dict[str, Any]) -> str:
    if document.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if document.get("spdxVersion"):
        return "spdx"
    raise SBOMParseError("unsupported SBOM: expected CycloneDX bomFormat or SPDX spdxVersion")


def parse_components(
    document: dict[str, Any], source: str
) -> tuple[str, list[Component], dict[str, Any]]:
    format_name = detect_format(document)
    if format_name == "cyclonedx":
        return format_name, _cyclonedx_components(document, source), _cyclonedx_metadata(document)
    return format_name, _spdx_components(document, source), _spdx_metadata(document)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _cyclonedx_components(document: dict[str, Any], source: str) -> list[Component]:
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise SBOMParseError("CycloneDX components must be an array")
    result: list[Component] = []
    for index, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            continue
        ref = _text(raw.get("bom-ref")) or f"component-{index + 1}"
        licenses = raw.get("licenses", [])
        license_ids: list[str] = []
        if isinstance(licenses, list):
            for item in licenses:
                if isinstance(item, dict):
                    license_data = item.get("license")
                    if isinstance(license_data, dict):
                        value = _text(license_data.get("id")) or _text(license_data.get("name"))
                        if value:
                            license_ids.append(value)
        result.append(Component(
            ref=ref,
            name=_text(raw.get("name")),
            version=_text(raw.get("version")),
            purl=_text(raw.get("purl")) or None,
            supplier=_text((raw.get("supplier") or {}).get("name"))
            if isinstance(raw.get("supplier"), dict) else None,
            licenses=tuple(license_ids),
            source=source,
        ))
    return result


def _spdx_components(document: dict[str, Any], source: str) -> list[Component]:
    raw_packages = document.get("packages", [])
    if not isinstance(raw_packages, list):
        raise SBOMParseError("SPDX packages must be an array")
    result: list[Component] = []
    for index, raw in enumerate(raw_packages):
        if not isinstance(raw, dict):
            continue
        ref = _text(raw.get("SPDXID")) or f"package-{index + 1}"
        external_refs = raw.get("externalRefs", [])
        purl: str | None = None
        if isinstance(external_refs, list):
            for item in external_refs:
                if isinstance(item, dict) and item.get("referenceType") == "purl":
                    purl = _text(item.get("referenceLocator")) or None
                    break
        license_value = _text(raw.get("licenseConcluded")) or _text(raw.get("licenseDeclared"))
        result.append(Component(
            ref=ref,
            name=_text(raw.get("name")),
            version=_text(raw.get("versionInfo")),
            purl=purl,
            supplier=_text(raw.get("supplier")) or None,
            licenses=(license_value,) if license_value else (),
            source=source,
        ))
    return result


def _cyclonedx_metadata(document: dict[str, Any]) -> dict[str, Any]:
    metadata = document.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _spdx_metadata(document: dict[str, Any]) -> dict[str, Any]:
    keys = ("SPDXID", "name", "documentNamespace", "creationInfo")
    return {key: document[key] for key in keys if key in document}
