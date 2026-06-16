from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from firmware_scanner import yara_runner


def test_missing_rules_file_returns_error(synthetic_firmware_file, tmp_path):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=tmp_path / "nonexistent.yar")
    assert result["error"] is not None
    assert result["matches"] == []


def test_result_has_required_keys(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    assert "matches" in result
    assert "error" in result


def test_missing_yara_module_sets_error(synthetic_firmware_file, minimal_yara_rules_file):
    with patch.object(yara_runner, "_YARA_AVAILABLE", False):
        result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    assert result["error"] is not None
    assert result["matches"] == []


@pytest.mark.requires_yara
def test_matches_rsa_key(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    assert result["error"] is None
    rule_names = [m["rule"] for m in result["matches"]]
    assert "TestRSAKey" in rule_names


@pytest.mark.requires_yara
def test_matches_admin_credential(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    assert result["error"] is None
    rule_names = [m["rule"] for m in result["matches"]]
    assert "TestAdminCredential" in rule_names


@pytest.mark.requires_yara
def test_each_match_has_severity(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    for match in result["matches"]:
        assert "severity" in match
        assert match["severity"] in ("critical", "high", "medium", "low")


@pytest.mark.requires_yara
def test_no_matches_on_zero_file(all_zero_file, minimal_yara_rules_file):
    result = yara_runner.scan(all_zero_file, rules_path=minimal_yara_rules_file)
    assert result["matches"] == []


@pytest.mark.requires_yara
def test_match_has_required_fields(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    for match in result["matches"]:
        assert "rule" in match
        assert "namespace" in match
        assert "tags" in match
        assert "severity" in match
        assert "strings" in match
        assert isinstance(match["strings"], list)


@pytest.mark.requires_yara
def test_rsa_match_severity_is_critical(synthetic_firmware_file, minimal_yara_rules_file):
    result = yara_runner.scan(synthetic_firmware_file, rules_path=minimal_yara_rules_file)
    rsa_matches = [m for m in result["matches"] if m["rule"] == "TestRSAKey"]
    assert len(rsa_matches) >= 1
    assert rsa_matches[0]["severity"] == "critical"
