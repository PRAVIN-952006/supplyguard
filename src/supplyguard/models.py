from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    ref: str
    name: str
    version: str
    purl: str | None
    supplier: str | None
    licenses: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    component_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
        }
        if self.component_ref is not None:
            result["component_ref"] = self.component_ref
        return result


@dataclass
class AuditResult:
    format: str
    components: list[Component] = field(default_factory=list)
    references: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "components": len(self.components),
            "errors": sum(item.severity == "error" for item in self.findings),
            "warnings": sum(item.severity == "warning" for item in self.findings),
            "info": sum(item.severity == "info" for item in self.findings),
        }

    @property
    def passed(self) -> bool:
        return not any(item.severity == "error" for item in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "metadata": self.metadata,
            "counts": self.counts,
            "passed": self.passed,
            "references": len(self.references),
            "findings": [item.as_dict() for item in self.findings],
        }
