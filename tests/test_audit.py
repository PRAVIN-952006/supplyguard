import json
from pathlib import Path

from supplyguard.audit import Policy, audit
from supplyguard.parsers import load_document, parse_components

FIXTURES = Path(__file__).parent / "fixtures"


def result_for(name: str, policy: Policy | None = None):
    document = load_document(FIXTURES / name)
    format_name, components, metadata = parse_components(document, name)
    return audit(format_name, components, metadata, policy or Policy())


def test_valid_cyclonedx_passes():
    result = result_for("valid-cyclonedx.json")
    assert result.passed
    assert result.counts["components"] == 2


def test_missing_purl_is_error():
    result = result_for("missing-purl.json")
    assert not result.passed
    assert any(item.rule_id == "SG005" for item in result.findings)


def test_duplicate_refs_are_error():
    result = result_for("duplicate-ref.json")
    assert any(item.rule_id == "SG002" for item in result.findings)


def test_spdx_package_url_is_supported():
    result = result_for("valid-spdx.json")
    assert result.passed
    assert result.format == "spdx"


def test_json_output_is_serializable():
    result = result_for("valid-cyclonedx.json")
    json.dumps(result.as_dict())
