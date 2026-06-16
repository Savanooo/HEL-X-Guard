from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from firmware_scanner import hashing, entropy, strings_scan, binwalk_runner, yara_runner, risk_scoring, report


def _build_report(fw_path: Path, yara_rules: Path) -> dict:
    hash_r    = hashing.hash_file(fw_path)
    entropy_r = entropy.analyze(fw_path)
    strings_r = strings_scan.scan(fw_path)
    binwalk_r = binwalk_runner.scan(fw_path)
    yara_r    = yara_runner.scan(fw_path, rules_path=yara_rules)
    risk_r    = risk_scoring.score(entropy_r, strings_r, yara_r, binwalk_r)
    return report.build(fw_path, hash_r, entropy_r, strings_r, binwalk_r, yara_r, risk_r)


@pytest.mark.integration
def test_end_to_end_report(synthetic_firmware_file, minimal_yara_rules_file, tmp_path):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    out = tmp_path / "report.json"
    report.write(rpt, out)
    loaded = json.loads(out.read_text())
    assert "scan_id" in loaded
    assert "file" in loaded
    assert "entropy" in loaded
    assert "strings" in loaded
    assert "binwalk" in loaded
    assert "yara" in loaded
    assert "risk" in loaded


def test_scan_id_is_uuid(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    uid = rpt["scan_id"]
    parsed = uuid.UUID(uid)
    assert str(parsed) == uid


def test_file_section(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    f = rpt["file"]
    assert f["name"] == synthetic_firmware_file.name
    assert f["size"]["bytes"] == synthetic_firmware_file.stat().st_size
    assert "md5" in f["hashes"]
    assert "sha1" in f["hashes"]
    assert "sha256" in f["hashes"]


def test_entropy_section(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    e = rpt["entropy"]
    assert isinstance(e["overall"], float)
    assert len(e["blocks"]) > 0
    assert isinstance(e["interpretation"], str)


def test_strings_section(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    s = rpt["strings"]
    assert s["total"] >= s["suspicious_count"]
    assert s["suspicious_count"] == len(s["suspicious"])


def test_risk_level_valid(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    assert rpt["risk"]["level"] in ("informational", "low", "medium", "high", "critical")


def test_risk_score_in_range(synthetic_firmware_file, minimal_yara_rules_file):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    assert 0 <= rpt["risk"]["score"] <= 100


def test_json_round_trip(synthetic_firmware_file, minimal_yara_rules_file, tmp_path):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    out = tmp_path / "report.json"
    report.write(rpt, out)
    loaded = json.loads(out.read_text())
    assert loaded["scan_id"] == rpt["scan_id"]
    assert loaded["risk"]["score"] == rpt["risk"]["score"]


def test_write_creates_file(synthetic_firmware_file, minimal_yara_rules_file, tmp_path):
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    out = tmp_path / "out" / "report.json"
    out.parent.mkdir(parents=True)
    report.write(rpt, out)
    assert out.exists()


def test_synthetic_firmware_is_high_risk(synthetic_firmware_file, minimal_yara_rules_file):
    """The synthetic firmware embeds private key + credentials → should be high or critical."""
    rpt = _build_report(synthetic_firmware_file, minimal_yara_rules_file)
    assert rpt["risk"]["level"] in ("high", "critical")


def test_all_zero_file_is_low_risk(all_zero_file, minimal_yara_rules_file):
    """Zero-byte file has no strings, no YARA matches, low entropy → informational."""
    rpt = _build_report(all_zero_file, minimal_yara_rules_file)
    assert rpt["risk"]["level"] in ("informational", "low")
    assert rpt["entropy"]["overall"] == 0.0
