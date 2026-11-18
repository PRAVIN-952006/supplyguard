from pathlib import Path

from supplyguard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_returns_failure_for_invalid_policy_input(capsys):
    assert main(["--max-missing-version", "-1", str(FIXTURES / "valid-cyclonedx.json")]) == 2
    assert "non-negative" in capsys.readouterr().err


def test_cli_json_output(capsys):
    assert main(["--format", "json", str(FIXTURES / "valid-cyclonedx.json")]) == 0
    assert '"passed": true' in capsys.readouterr().out
