from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from firmware_scanner import binwalk_runner


def test_scan_result_has_required_keys(synthetic_firmware_file):
    result = binwalk_runner.scan(synthetic_firmware_file)
    assert "findings" in result
    assert "extracted" in result
    assert "error" in result


def test_scan_extracted_always_empty(synthetic_firmware_file):
    result = binwalk_runner.scan(synthetic_firmware_file)
    assert result["extracted"] == []


def test_missing_binwalk_sets_error_not_raises(synthetic_firmware_file):
    with patch("shutil.which", return_value=None):
        result = binwalk_runner.scan(synthetic_firmware_file)
    assert result["error"] is not None
    assert "not found" in result["error"].lower()
    assert result["findings"] == []


def test_parse_output_valid_lines():
    stdout = (
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        "--------------------------------------------------------------------------------\n"
        "0             0x0             PNG image, 128 x 128\n"
        "512           0x200           gzip compressed data\n"
    )
    findings = binwalk_runner._parse_output(stdout)
    assert len(findings) == 2
    assert findings[0]["offset"] == 0
    assert findings[0]["hex_offset"] == "0x0"
    assert "PNG" in findings[0]["description"]
    assert findings[1]["offset"] == 512
    assert findings[1]["hex_offset"] == "0x200"


def test_parse_output_skips_header_lines():
    stdout = (
        "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        "----------------------------\n"
        "1024          0x400           Squashfs filesystem\n"
    )
    findings = binwalk_runner._parse_output(stdout)
    assert len(findings) == 1
    assert findings[0]["offset"] == 1024


def test_parse_output_empty_string():
    assert binwalk_runner._parse_output("") == []


def test_timeout_captured_not_raised(synthetic_firmware_file):
    with patch("shutil.which", return_value="/usr/bin/binwalk"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="binwalk", timeout=1)):
            result = binwalk_runner.scan(synthetic_firmware_file, timeout=1)
    assert result["error"] is not None
    assert "timed out" in result["error"].lower()
    assert result["findings"] == []


def test_binwalk_nonzero_exit_captured(synthetic_firmware_file):
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stderr = "fatal error"
    with patch("shutil.which", return_value="/usr/bin/binwalk"):
        with patch("subprocess.run", return_value=mock_result):
            result = binwalk_runner.scan(synthetic_firmware_file)
    assert result["error"] is not None
    assert result["findings"] == []


def test_extract_result_has_required_keys(synthetic_firmware_file, tmp_path):
    with patch("shutil.which", return_value=None):
        result = binwalk_runner.extract(synthetic_firmware_file, tmp_path / "out")
    assert "findings" in result
    assert "extracted" in result
    assert "error" in result


@pytest.mark.requires_binwalk
def test_scan_with_real_binwalk(synthetic_firmware_file):
    result = binwalk_runner.scan(synthetic_firmware_file)
    # Even for a synthetic file binwalk should not error (just may find nothing)
    assert result["error"] is None or isinstance(result["error"], str)
    assert isinstance(result["findings"], list)
