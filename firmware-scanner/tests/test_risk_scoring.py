from __future__ import annotations

import pytest

from firmware_scanner import risk_scoring


def _make_inputs(
    overall_entropy: float = 4.0,
    suspicious: list | None = None,
    yara_matches: list | None = None,
) -> tuple[dict, dict, dict]:
    entropy_result = {
        "overall": overall_entropy,
        "blocks": [],
        "interpretation": "plain or low-entropy data",
    }
    strings_result = {
        "total": len(suspicious or []),
        "suspicious": suspicious or [],
        "suspicious_count": len(suspicious or []),
    }
    yara_result = {
        "matches": yara_matches or [],
        "error": None,
    }
    return entropy_result, strings_result, yara_result


def test_zero_input_is_informational():
    e, s, y = _make_inputs()
    result = risk_scoring.score(e, s, y)
    assert result["score"] == 0
    assert result["level"] == "informational"
    assert result["reasons"] == []


def test_high_entropy_adds_15():
    e, s, y = _make_inputs(overall_entropy=7.6)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == 15
    assert any("entropy" in r.lower() for r in result["reasons"])


def test_credential_single():
    suspicious = [{"category": "CREDENTIAL", "value": "password=x", "offset": 0, "encoding": "ascii"}]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.W_CREDENTIAL


def test_credential_capped():
    suspicious = [
        {"category": "CREDENTIAL", "value": f"password={i}", "offset": i, "encoding": "ascii"}
        for i in range(20)
    ]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] <= risk_scoring.CAP_CREDENTIAL


def test_private_key_adds_30():
    suspicious = [{"category": "PRIVATE_KEY", "value": "-----BEGIN RSA PRIVATE KEY-----", "offset": 0, "encoding": "ascii"}]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.W_PRIVATE_KEY


def test_certificate_adds_30():
    suspicious = [{"category": "CERTIFICATE", "value": "-----BEGIN CERTIFICATE-----", "offset": 0, "encoding": "ascii"}]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.W_PRIVATE_KEY


def test_api_key_adds_20():
    suspicious = [{"category": "API_KEY", "value": "AKIAIOSFODNN7EXAMPLE", "offset": 0, "encoding": "ascii"}]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.W_API_KEY


def test_api_key_capped():
    suspicious = [
        {"category": "API_KEY", "value": f"AKIA{'X'*16}{i}", "offset": i, "encoding": "ascii"}
        for i in range(10)
    ]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] <= risk_scoring.CAP_API_KEY


def test_yara_critical_adds_40():
    yara_matches = [{"rule": "TestRule", "severity": "critical", "tags": [], "strings": [], "namespace": "default"}]
    e, s, y = _make_inputs(yara_matches=yara_matches)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.YARA_WEIGHTS["critical"]


def test_yara_high_adds_20():
    yara_matches = [{"rule": "TestRule", "severity": "high", "tags": [], "strings": [], "namespace": "default"}]
    e, s, y = _make_inputs(yara_matches=yara_matches)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == risk_scoring.YARA_WEIGHTS["high"]


def test_shell_command_capped():
    suspicious = [
        {"category": "SHELL_COMMAND", "value": f"wget http://x.com/{i}", "offset": i, "encoding": "ascii"}
        for i in range(20)
    ]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    # Shell command contribution should not exceed CAP_SHELL_CMD
    assert result["score"] <= risk_scoring.CAP_SHELL_CMD


def test_debug_keyword_capped():
    suspicious = [
        {"category": "DEBUG_KEYWORD", "value": "backdoor", "offset": i, "encoding": "ascii"}
        for i in range(10)
    ]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] <= risk_scoring.CAP_DEBUG


def test_score_clamped_at_100():
    suspicious = (
        [{"category": "PRIVATE_KEY", "value": "BEGIN KEY", "offset": 0, "encoding": "ascii"}]
        + [{"category": "CREDENTIAL", "value": f"pw={i}", "offset": i+1, "encoding": "ascii"} for i in range(20)]
        + [{"category": "API_KEY", "value": f"AKIA{'X'*16}", "offset": 1000+i, "encoding": "ascii"} for i in range(5)]
        + [{"category": "DEBUG_KEYWORD", "value": "backdoor", "offset": 2000+i, "encoding": "ascii"} for i in range(5)]
    )
    yara_matches = [
        {"rule": f"Rule{i}", "severity": "critical", "tags": [], "strings": [], "namespace": "default"}
        for i in range(5)
    ]
    e, s, y = _make_inputs(overall_entropy=8.0, suspicious=suspicious, yara_matches=yara_matches)
    result = risk_scoring.score(e, s, y)
    assert result["score"] == 100


def test_level_thresholds():
    assert risk_scoring._level(0)   == "informational"
    assert risk_scoring._level(1)   == "low"
    assert risk_scoring._level(25)  == "low"
    assert risk_scoring._level(26)  == "medium"
    assert risk_scoring._level(50)  == "medium"
    assert risk_scoring._level(51)  == "high"
    assert risk_scoring._level(75)  == "high"
    assert risk_scoring._level(76)  == "critical"
    assert risk_scoring._level(100) == "critical"


def test_reasons_non_empty_when_score_positive():
    suspicious = [{"category": "API_KEY", "value": "AKIAIOSFODNN7EXAMPLE", "offset": 0, "encoding": "ascii"}]
    e, s, y = _make_inputs(suspicious=suspicious)
    result = risk_scoring.score(e, s, y)
    assert result["score"] > 0
    assert len(result["reasons"]) > 0


def test_yara_reason_includes_rule_name():
    yara_matches = [{"rule": "MiraiBotnet", "severity": "critical", "tags": [], "strings": [], "namespace": "default"}]
    e, s, y = _make_inputs(yara_matches=yara_matches)
    result = risk_scoring.score(e, s, y)
    assert any("MiraiBotnet" in r for r in result["reasons"])
