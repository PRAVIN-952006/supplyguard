import json

import pytest

from supplyguard.parsers import SBOMParseError, load_document, parse_components


def test_unsupported_cyclonedx_version_is_rejected(tmp_path):
    path = tmp_path / "unsupported.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "2.0"}))
    with pytest.raises(SBOMParseError, match="unsupported CycloneDX"):
        parse_components(load_document(path), str(path))


def test_oversized_input_is_rejected(tmp_path):
    path = tmp_path / "large.json"
    path.write_text("{}")
    with pytest.raises(SBOMParseError, match="safety limit"):
        load_document(path, max_bytes=1)


def test_malformed_json_is_rejected(tmp_path):
    path = tmp_path / "malformed.json"
    path.write_text("{not-json")
    with pytest.raises(SBOMParseError, match="valid UTF-8 JSON"):
        load_document(path)
