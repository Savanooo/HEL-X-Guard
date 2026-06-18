"""Tests for checksec.py — ELF security mitigation checker."""
from __future__ import annotations

from pathlib import Path

import pytest

from firmware_scanner import checksec


# ── Helpers ───────────────────────────────────────────────────────────────────

def _lief_available() -> bool:
    try:
        import lief  # noqa: F401
        return True
    except ImportError:
        return False


requires_lief = pytest.mark.skipif(not _lief_available(), reason="lief not installed")


# ── Non-ELF inputs ────────────────────────────────────────────────────────────

def test_raw_binary_not_elf(synthetic_firmware_file):
    result = checksec.analyze(synthetic_firmware_file)
    # May fail gracefully without lief, or return is_elf=False for non-ELF
    assert isinstance(result, dict)
    assert "is_elf" in result


def test_raw_binary_is_elf_false(synthetic_firmware_file):
    result = checksec.analyze(synthetic_firmware_file)
    # The synthetic fixture starts with PNG magic, not ELF — should not be ELF
    if not result.get("error") or "lief" not in (result.get("error") or ""):
        assert result["is_elf"] is False


def test_all_zero_not_elf(all_zero_file):
    result = checksec.analyze(all_zero_file)
    assert isinstance(result, dict)
    assert "is_elf" in result


# ── Return structure ──────────────────────────────────────────────────────────

def test_returns_dict(synthetic_firmware_file):
    result = checksec.analyze(synthetic_firmware_file)
    assert isinstance(result, dict)


def test_error_field_present(synthetic_firmware_file):
    result = checksec.analyze(synthetic_firmware_file)
    assert "error" in result


def test_is_elf_field_present(synthetic_firmware_file):
    result = checksec.analyze(synthetic_firmware_file)
    assert "is_elf" in result


@requires_lief
def test_elf_result_has_security_fields(tmp_path):
    """For a real ELF binary (Python interpreter), verify field set."""
    import sys
    python_exe = Path(sys.executable)
    if not python_exe.exists():
        pytest.skip("Python executable not found")

    result = checksec.analyze(python_exe)
    # May or may not be ELF depending on platform
    assert isinstance(result, dict)
    assert "is_elf" in result
    if result["is_elf"]:
        for field in ("nx", "pie", "relro", "canary", "fortify"):
            assert field in result, f"missing field: {field}"
        assert result["relro"] in ("none", "partial", "full")


# ── No-crash guarantee ────────────────────────────────────────────────────────

def test_no_exception_on_uniform_file(uniform_file):
    result = checksec.analyze(uniform_file)
    assert isinstance(result, dict)


def test_no_exception_on_zero_file(all_zero_file):
    result = checksec.analyze(all_zero_file)
    assert isinstance(result, dict)
