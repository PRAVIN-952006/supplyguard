from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .models import AuditResult, Component, Finding

_PURL_RE = re.compile(r"^pkg:[a-z0-9.+-]+/[^\s]+$", re.IGNORECASE)
_SEVERITIES = ("error", "warning", "info")


@dataclass(frozen=True)
class Policy:
    require_purl: bool = True
    require_supplier: bool = False
    require_license: bool = False
    max_components_without_version: int = 0


def audit(
    format_name: str,
    components: Iterable[Component],
    metadata: dict[str, object],
    policy: Policy,
    references: Iterable[str] = (),
) -> AuditResult:
    component_list = list(components)
    reference_list = tuple(references)
    result = AuditResult(
        format=format_name,
        components=component_list,
        references=reference_list,
        metadata=metadata,
    )
    if not component_list:
        result.findings.append(Finding("SG001", "error", "SBOM contains no components"))
        return result

    refs = Counter(component.ref for component in component_list)
    known_refs = set(refs)
    for reference in reference_list:
        if reference not in known_refs:
            result.findings.append(Finding(
                "SG011", "error", f"dependency references unknown component: {reference}", reference
            ))
    for ref, count in refs.items():
        if count > 1:
            result.findings.append(Finding(
                "SG002", "error", f"duplicate component reference: {ref}", ref
            ))

    missing_versions = 0
    for component in component_list:
        if not component.name:
            result.findings.append(Finding(
                "SG003", "error", "component is missing a name", component.ref
            ))
        if not component.version:
            missing_versions += 1
            result.findings.append(Finding(
                "SG004", "warning", "component is missing a version", component.ref
            ))
        if policy.require_purl and not component.purl:
            result.findings.append(Finding(
                "SG005", "error", "component is missing a package URL (purl)", component.ref
            ))
        elif component.purl and not _PURL_RE.match(component.purl):
            result.findings.append(Finding(
                "SG006", "error", "component has an invalid package URL", component.ref
            ))
        if policy.require_supplier and not component.supplier:
            result.findings.append(Finding(
                "SG007", "warning", "component is missing supplier information", component.ref
            ))
        if policy.require_license and not component.licenses:
            result.findings.append(Finding(
                "SG008", "warning", "component has no declared license", component.ref
            ))

    if missing_versions > policy.max_components_without_version:
        result.findings.append(Finding(
            "SG009",
            "error",
            f"{missing_versions} component(s) lack versions; policy allows "
            f"{policy.max_components_without_version}",
        ))
    if not metadata:
        result.findings.append(Finding("SG010", "warning", "SBOM has no metadata section"))
    return result


def severity_rank(severity: str) -> int:
    return _SEVERITIES.index(severity) if severity in _SEVERITIES else len(_SEVERITIES)
