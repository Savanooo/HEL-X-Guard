"""Tests for components.py — SBOM embedded library detection."""
from __future__ import annotations

from pathlib import Path

import pytest

from firmware_scanner import components


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def freertos_binary(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("comp")
    p   = tmp / "freertos.bin"
    p.write_bytes(b"\x00" * 32 + b"FreeRTOS V10.4.3\x00" + b"\x00" * 64)
    return p


@pytest.fixture(scope="session")
def multi_component_binary(tmp_path_factory) -> Path:
    """Binary with several component banners."""
    tmp = tmp_path_factory.mktemp("comp")
    p   = tmp / "multi.bin"
    content = (
        b"\x00" * 16
        + b"FreeRTOS V10.4.3\x00"
        + b"\x00" * 16
        + b"lwIP 2.1.2\x00"
        + b"\x00" * 16
        + b"libcurl/7.81.0\x00"
        + b"\x00" * 16
        + b"BusyBox v1.34.1 (2022-01-01)\x00"
        + b"\x00" * 32
    )
    p.write_bytes(content)
    return p


@pytest.fixture(scope="session")
def no_component_binary(all_zero_file) -> Path:
    return all_zero_file


# ── Return structure ──────────────────────────────────────────────────────────

def test_returns_dict(synthetic_firmware_file):
    result = components.analyze(synthetic_firmware_file)
    assert isinstance(result, dict)


def test_required_keys(synthetic_firmware_file):
    result = components.analyze(synthetic_firmware_file)
    assert "components" in result
    assert "count"      in result
    assert "error"      in result


def test_components_is_list(synthetic_firmware_file):
    result = components.analyze(synthetic_firmware_file)
    assert isinstance(result["components"], list)


def test_count_matches_list_length(synthetic_firmware_file):
    result = components.analyze(synthetic_firmware_file)
    assert result["count"] == len(result["components"])


def test_component_entry_structure(freertos_binary):
    result = components.analyze(freertos_binary)
    assert result["count"] > 0
    entry = result["components"][0]
    assert "component"      in entry
    assert "version"        in entry
    assert "evidence_offset" in entry
    assert "evidence"       in entry


# ── Positive detections ────────────────────────────────────────────────────────

def test_detects_freertos(freertos_binary):
    result = components.analyze(freertos_binary)
    names  = {c["component"] for c in result["components"]}
    assert "FreeRTOS" in names


def test_freertos_version_correct(freertos_binary):
    result = components.analyze(freertos_binary)
    fr     = next(c for c in result["components"] if c["component"] == "FreeRTOS")
    assert fr["version"] == "10.4.3"


def test_detects_multiple_components(multi_component_binary):
    result = components.analyze(multi_component_binary)
    names  = {c["component"] for c in result["components"]}
    assert "FreeRTOS" in names
    assert "lwIP"     in names
    assert "libcurl"  in names
    assert "BusyBox"  in names


def test_no_duplicate_components(multi_component_binary):
    result = components.analyze(multi_component_binary)
    names  = [c["component"] for c in result["components"]]
    assert len(names) == len(set(names)), "Duplicate component entries found"


def test_evidence_offset_is_int(freertos_binary):
    result = components.analyze(freertos_binary)
    for c in result["components"]:
        assert isinstance(c["evidence_offset"], int)


# ── Negative / edge cases ─────────────────────────────────────────────────────

def test_no_components_in_zero_file(no_component_binary):
    result = components.analyze(no_component_binary)
    assert result["count"] == 0
    assert result["components"] == []


def test_no_error_on_valid_input(freertos_binary):
    result = components.analyze(freertos_binary)
    assert result["error"] is None


def test_synthetic_firmware_does_not_crash(synthetic_firmware_file):
    result = components.analyze(synthetic_firmware_file)
    assert isinstance(result, dict)
    assert "components" in result
