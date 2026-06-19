"""Tests for Feature 6: firmware version tracking and regression analysis.

Tests the helper functions and regression logic in isolation — no database
or running server required.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from api.routers.firmware import (
    _stem,
    _yara_set,
    _string_set,
    _scan_to_meta,
)


# ── _stem helper ──────────────────────────────────────────────────────────────

def test_stem_strips_bin_extension():
    assert _stem("firmware_v1.bin") == "firmware"


def test_stem_strips_hex_extension():
    assert _stem("router_2.0.hex") == "router"


def test_stem_strips_elf_extension():
    assert _stem("app_v3.1.4.elf") == "app"


def test_stem_strips_version_suffix():
    assert _stem("camera_fw-v2.3.1.bin") == "camera_fw"


def test_stem_strips_rc_suffix():
    assert _stem("device_v1.0_rc1.bin") == "device"


def test_stem_lowercases():
    assert _stem("FirmWare_V1.BIN") == "firmware"


def test_stem_no_extension_returns_lowercased():
    s = _stem("plainname")
    assert s == "plainname"


def test_stem_same_device_different_versions():
    """Two version filenames for the same device yield identical stems."""
    assert _stem("sensor_v1.0.bin") == _stem("sensor_v2.0.bin")


# ── _yara_set helper ──────────────────────────────────────────────────────────

def test_yara_set_empty_report():
    assert _yara_set({}) == set()


def test_yara_set_no_matches():
    assert _yara_set({"yara": {"matches": []}}) == set()


def test_yara_set_extracts_rule_names():
    report = {"yara": {"matches": [
        {"rule": "HardcodedPassword", "severity": "high"},
        {"rule": "EmbeddedRSAPrivateKey", "severity": "critical"},
    ]}}
    assert _yara_set(report) == {"HardcodedPassword", "EmbeddedRSAPrivateKey"}


def test_yara_set_deduplicates():
    report = {"yara": {"matches": [
        {"rule": "SameRule"}, {"rule": "SameRule"},
    ]}}
    assert _yara_set(report) == {"SameRule"}


# ── _string_set helper ────────────────────────────────────────────────────────

def test_string_set_empty_report():
    assert _string_set({}) == set()


def test_string_set_extracts_value_category_tuples():
    report = {"strings": {"suspicious": [
        {"value": "admin123", "category": "CREDENTIAL"},
        {"value": "192.168.1.1", "category": "IP"},
    ]}}
    result = _string_set(report)
    assert ("admin123", "CREDENTIAL") in result
    assert ("192.168.1.1", "IP") in result


def test_string_set_deduplicates():
    report = {"strings": {"suspicious": [
        {"value": "same", "category": "URL"},
        {"value": "same", "category": "URL"},
    ]}}
    assert len(_string_set(report)) == 1


# ── regression diff logic ─────────────────────────────────────────────────────

def _make_report(*, yara_rules=(), strings=()) -> dict:
    """Build a minimal report dict for regression testing."""
    return {
        "yara": {"matches": [{"rule": r, "severity": "medium"} for r in yara_rules]},
        "strings": {
            "suspicious": [{"value": v, "category": c} for v, c in strings],
            "suspicious_count": len(strings),
        },
        "entropy": {"overall": 6.5},
    }


def test_yara_appeared_between_versions():
    """Rules present in scan_b but not scan_a appear in appeared set."""
    report_a = _make_report(yara_rules=["RuleA"])
    report_b = _make_report(yara_rules=["RuleA", "RuleB"])
    appeared = sorted(_yara_set(report_b) - _yara_set(report_a))
    assert appeared == ["RuleB"]


def test_yara_resolved_between_versions():
    """Rules present in scan_a but not scan_b appear in resolved set."""
    report_a = _make_report(yara_rules=["OldRule", "StillHere"])
    report_b = _make_report(yara_rules=["StillHere"])
    resolved = sorted(_yara_set(report_a) - _yara_set(report_b))
    assert resolved == ["OldRule"]


def test_strings_appeared_between_versions():
    """Strings in scan_b but not scan_a appear in appeared set."""
    report_a = _make_report(strings=[("password", "CREDENTIAL")])
    report_b = _make_report(strings=[("password", "CREDENTIAL"), ("admin", "CREDENTIAL")])
    appeared = _string_set(report_b) - _string_set(report_a)
    assert ("admin", "CREDENTIAL") in appeared


def test_strings_removed_between_versions():
    """Strings in scan_a but not scan_b appear in removed set."""
    report_a = _make_report(strings=[("password", "CREDENTIAL"), ("debug", "DEBUG_KEYWORD")])
    report_b = _make_report(strings=[("password", "CREDENTIAL")])
    removed = _string_set(report_a) - _string_set(report_b)
    assert ("debug", "DEBUG_KEYWORD") in removed


def test_three_scan_lineage_appeared_removed():
    """3-scan lineage: correct appeared and removed sets for each step."""
    r1 = _make_report(yara_rules=["A"], strings=[("pw", "CREDENTIAL")])
    r2 = _make_report(yara_rules=["A", "B"], strings=[("pw", "CREDENTIAL"), ("key", "API_KEY")])
    r3 = _make_report(yara_rules=["B", "C"], strings=[("key", "API_KEY")])

    # step 1→2
    y_appeared_12 = _yara_set(r2) - _yara_set(r1)
    y_resolved_12 = _yara_set(r1) - _yara_set(r2)
    s_appeared_12 = _string_set(r2) - _string_set(r1)
    s_removed_12 = _string_set(r1) - _string_set(r2)

    assert y_appeared_12 == {"B"}
    assert y_resolved_12 == set()
    assert ("key", "API_KEY") in s_appeared_12
    assert len(s_removed_12) == 0

    # step 2→3
    y_appeared_23 = _yara_set(r3) - _yara_set(r2)
    y_resolved_23 = _yara_set(r2) - _yara_set(r3)
    s_appeared_23 = _string_set(r3) - _string_set(r2)
    s_removed_23 = _string_set(r2) - _string_set(r3)

    assert y_appeared_23 == {"C"}
    assert y_resolved_23 == {"A"}
    assert len(s_appeared_23) == 0
    assert ("pw", "CREDENTIAL") in s_removed_23


def test_identical_scans_no_delta():
    """Two identical reports produce empty appeared and removed sets."""
    report = _make_report(yara_rules=["X"], strings=[("val", "URL")])
    assert _yara_set(report) - _yara_set(report) == set()
    assert _string_set(report) - _string_set(report) == set()


# ── _scan_to_meta helper ──────────────────────────────────────────────────────

def _fake_scan(**kwargs) -> object:
    defaults = {
        "id": "scan-001",
        "filename": "firmware_v1.bin",
        "device_label": None,
        "risk_score": 45.0,
        "risk_level": "medium",
        "created_at": None,
        "completed_at": None,
        "file_size": 102400,
        "sha256": "abc123",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_scan_to_meta_keys():
    meta = _scan_to_meta(_fake_scan(), {})
    for key in ("id", "filename", "device_label", "risk_score", "risk_level",
                "created_at", "completed_at", "entropy", "file_size",
                "yara_count", "suspicious_count", "sha256"):
        assert key in meta, f"missing key: {key}"


def test_scan_to_meta_yara_count_from_report():
    report = _make_report(yara_rules=["R1", "R2", "R3"])
    meta = _scan_to_meta(_fake_scan(), report)
    assert meta["yara_count"] == 3


def test_scan_to_meta_entropy_from_report():
    report = {"entropy": {"overall": 7.8}, "yara": {"matches": []}, "strings": {"suspicious": [], "suspicious_count": 0}}
    meta = _scan_to_meta(_fake_scan(), report)
    assert meta["entropy"] == 7.8


def test_scan_to_meta_empty_report_defaults():
    meta = _scan_to_meta(_fake_scan(), {})
    assert meta["yara_count"] == 0
    assert meta["suspicious_count"] == 0
    assert meta["entropy"] is None
