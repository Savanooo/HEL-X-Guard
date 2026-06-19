"""Tests for Feature 3: compliance mapping (CWE + EU CRA + IEC 62443-4-2 + FDA)."""
from __future__ import annotations

import pytest
from firmware_scanner import compliance


# ── helpers ───────────────────────────────────────────────────────────────────

def _report(*, yara_rules=(), string_cats=None, entropy=0.0, elf=None, checksec=None):
    """Build a minimal fake report dict for testing."""
    matches = [{"rule": r, "severity": "high"} for r in yara_rules]
    cat_counts = string_cats or {}
    report = {
        "yara":    {"matches": matches, "error": None},
        "strings": {"suspicious": [], "category_counts": cat_counts},
        "entropy": {"overall": entropy},
        "elf":     elf or {"is_elf": False},
        "checksec": checksec or {"is_elf": False},
    }
    return report


# ── import / structure ────────────────────────────────────────────────────────

def test_compliance_importable():
    from firmware_scanner import compliance as c  # noqa: F401
    assert hasattr(c, "analyze")


def test_compliance_map_loads():
    """compliance_map.json can be loaded and has the three top-level keys."""
    cmap = compliance._load_map()
    assert "yara_rules" in cmap
    assert "string_categories" in cmap
    assert "conditions" in cmap


def test_empty_report_returns_clean_structure():
    result = compliance.analyze({})
    assert result["error"] is None
    assert isinstance(result["mappings"], list)
    assert isinstance(result["summary"], dict)
    for std in ("cwe", "eu_cra", "iec_62443", "fda"):
        assert std in result["summary"]


# ── YARA rule mappings ────────────────────────────────────────────────────────

def test_yara_rule_maps_to_standards():
    """A known YARA rule match produces compliance entries."""
    result = compliance.analyze(_report(yara_rules=["HardcodedDefaultCredentials"]))
    assert result["error"] is None
    assert len(result["mappings"]) == 1
    m = result["mappings"][0]
    assert m["source"] == "yara:HardcodedDefaultCredentials"
    assert "CWE-798" in m["cwe"]
    assert any("Annex I" in r for r in m["eu_cra"])
    assert len(m["iec_62443"]) > 0
    assert len(m["fda"]) > 0


def test_unknown_yara_rule_ignored():
    """A YARA rule not in the map produces no mapping."""
    result = compliance.analyze(_report(yara_rules=["SomeUnknownRule"]))
    assert result["mappings"] == []


def test_multiple_yara_rules():
    """Multiple YARA matches produce one mapping each."""
    result = compliance.analyze(
        _report(yara_rules=["EmbeddedRSAPrivateKey", "WeakCryptographyIdentifiers"])
    )
    sources = {m["source"] for m in result["mappings"]}
    assert "yara:EmbeddedRSAPrivateKey" in sources
    assert "yara:WeakCryptographyIdentifiers" in sources


# ── String category mappings ──────────────────────────────────────────────────

def test_credential_string_category():
    """CREDENTIAL string category maps to CWE-798 and credential standards."""
    result = compliance.analyze(_report(string_cats={"CREDENTIAL": 3}))
    assert result["error"] is None
    cred_mappings = [m for m in result["mappings"] if m["source"] == "string:CREDENTIAL"]
    assert len(cred_mappings) == 1
    m = cred_mappings[0]
    assert "CWE-798" in m["cwe"]
    assert "3 instances" in m["finding"]


def test_debug_keyword_string_category():
    """DEBUG_KEYWORD category maps to CWE-912."""
    result = compliance.analyze(_report(string_cats={"DEBUG_KEYWORD": 1}))
    debug_maps = [m for m in result["mappings"] if m["source"] == "string:DEBUG_KEYWORD"]
    assert len(debug_maps) == 1
    assert "CWE-912" in debug_maps[0]["cwe"]


def test_unknown_string_category_ignored():
    """A string category not in the map is skipped without error."""
    result = compliance.analyze(_report(string_cats={"UNKNOWN_CAT": 5}))
    unknown = [m for m in result["mappings"] if "UNKNOWN_CAT" in m["source"]]
    assert unknown == []


# ── ELF / checksec condition mappings ────────────────────────────────────────

def test_no_nx_maps_to_cwe():
    """Missing NX protection maps to CWE-693."""
    elf = {"is_elf": True, "security": {"nx": False, "pie": True, "relro": "full"},
           "imported_symbols": ["__stack_chk_fail"], "exported_symbols": []}
    result = compliance.analyze(_report(elf=elf))
    nx_maps = [m for m in result["mappings"] if m["source"] == "condition:no_nx"]
    assert len(nx_maps) == 1
    assert "CWE-693" in nx_maps[0]["cwe"]


def test_no_stack_canary_maps_to_cwe():
    """Missing stack canary maps to CWE-121."""
    elf = {"is_elf": True, "security": {"nx": True, "pie": True, "relro": "full"},
           "imported_symbols": [], "exported_symbols": []}
    result = compliance.analyze(_report(elf=elf))
    canary_maps = [m for m in result["mappings"] if m["source"] == "condition:no_stack_canary"]
    assert len(canary_maps) == 1
    assert "CWE-121" in canary_maps[0]["cwe"]


def test_partial_relro_maps():
    """Partial RELRO produces a mapping."""
    elf = {"is_elf": True, "security": {"nx": True, "pie": True, "relro": "partial"},
           "imported_symbols": ["__stack_chk_fail"], "exported_symbols": []}
    result = compliance.analyze(_report(elf=elf))
    relro_maps = [m for m in result["mappings"] if m["source"] == "condition:partial_relro"]
    assert len(relro_maps) == 1


# ── High entropy condition ────────────────────────────────────────────────────

def test_high_entropy_maps():
    """Overall entropy > 7.5 triggers a compliance condition."""
    result = compliance.analyze(_report(entropy=7.8))
    entropy_maps = [m for m in result["mappings"] if m["source"] == "condition:high_entropy"]
    assert len(entropy_maps) == 1
    assert "CWE-261" in entropy_maps[0]["cwe"]


def test_normal_entropy_no_mapping():
    """Entropy ≤ 7.5 does not trigger the high-entropy condition."""
    result = compliance.analyze(_report(entropy=6.5))
    entropy_maps = [m for m in result["mappings"] if m["source"] == "condition:high_entropy"]
    assert entropy_maps == []


# ── Summary deduplication ─────────────────────────────────────────────────────

def test_summary_deduplicates_standards():
    """The same standard reference appearing in multiple mappings appears once in summary."""
    result = compliance.analyze(
        _report(yara_rules=["HardcodedDefaultCredentials", "HardcodedWiFiCredentials"])
    )
    cwe_set = set(result["summary"]["cwe"])
    # CWE-798 appears in both rules; should appear once in summary
    assert result["summary"]["cwe"].count("CWE-798") == 1


def test_summary_sorted():
    """Summary lists are sorted."""
    result = compliance.analyze(
        _report(yara_rules=["EmbeddedRSAPrivateKey", "MiraiBotnet", "TelnetBackdoor"])
    )
    for std in ("cwe", "eu_cra", "iec_62443", "fda"):
        lst = result["summary"][std]
        assert lst == sorted(lst), f"{std} is not sorted"


# ── Deduplication of sources ──────────────────────────────────────────────────

def test_duplicate_yara_rules_deduplicated():
    """If somehow the same rule appears twice, only one mapping is emitted."""
    report = {
        "yara": {"matches": [
            {"rule": "AWSAccessKey", "severity": "high"},
            {"rule": "AWSAccessKey", "severity": "high"},
        ]},
        "strings": {"suspicious": [], "category_counts": {}},
        "entropy": {"overall": 0.0},
        "elf": {"is_elf": False},
        "checksec": {"is_elf": False},
    }
    result = compliance.analyze(report)
    sources = [m["source"] for m in result["mappings"]]
    assert sources.count("yara:AWSAccessKey") == 1


# ── Error resilience ──────────────────────────────────────────────────────────

def test_analyze_returns_on_bad_input():
    """analyze() with completely unexpected input returns error structure, never raises."""
    result = compliance.analyze(None)  # type: ignore[arg-type]
    assert "error" in result
    assert isinstance(result["mappings"], list)


def test_plural_and_singular_instance_label():
    """Single instance uses singular, multiple use plural."""
    single = compliance.analyze(_report(string_cats={"CREDENTIAL": 1}))
    plural = compliance.analyze(_report(string_cats={"CREDENTIAL": 2}))
    assert "1 instance)" in single["mappings"][0]["finding"]
    assert "2 instances)" in plural["mappings"][0]["finding"]
