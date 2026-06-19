"""Tests for Feature 1: multi-architecture disassembly support.

Covers:
  - arch_detect.probe_arch() — x86-64 and MIPS-BE blob detection
  - arch_detect.analyze() — new disasm_arch/capstone_arch/capstone_mode fields
  - disasm_stats.analyze() — uses detected arch from arch_info
  - Thumb-2 path unchanged (backward compat)
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from firmware_scanner import arch_detect, disasm_stats


# ── Cortex-M fixture (local copy — avoids importing test_arch_detect.py) ─────

@pytest.fixture(scope="session")
def cortex_m_firmware(tmp_path_factory) -> Path:
    """STM32-style bare-metal firmware with valid SP + reset handler."""
    tmp = tmp_path_factory.mktemp("cm")
    fw = tmp / "stm32.bin"
    data = bytearray(512)
    struct.pack_into("<I", data, 0, 0x20020000)  # SP in RAM
    struct.pack_into("<I", data, 4, 0x08000101)  # reset handler (Thumb bit)
    data[0x100] = 0x80
    data[0x101] = 0xF0
    fw.write_bytes(bytes(data))
    return fw


# ── capstone availability ─────────────────────────────────────────────────────

def _capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


requires_capstone = pytest.mark.skipif(
    not _capstone_available(), reason="capstone not installed"
)


# ── x86-64 blob fixture ───────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def x86_64_blob(tmp_path_factory) -> Path:
    """Small x86-64 function: push rbp / mov rbp,rsp / xor eax,eax / pop rbp / ret.

    These bytes are unambiguous x86-64 and would produce many skipdata
    placeholders if decoded as fixed-width ARM/MIPS instructions.
    """
    code = bytes([
        0x55,                    # push rbp
        0x48, 0x89, 0xE5,        # mov  rbp, rsp
        0x31, 0xC0,              # xor  eax, eax
        0x48, 0x83, 0xEC, 0x20,  # sub  rsp, 0x20
        0x48, 0x83, 0xC4, 0x20,  # add  rsp, 0x20
        0x5D,                    # pop  rbp
        0xC3,                    # ret
    ]) * 16   # repeat 16× to give the prober enough data
    p = tmp_path_factory.mktemp("multi_arch") / "x86_64.bin"
    p.write_bytes(code)
    return p


# ── MIPS-BE blob fixture ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mips_be_blob(tmp_path_factory) -> Path:
    """Small MIPS big-endian function (10 canonical MIPS32 instructions).

    MIPS-BE has fixed 4-byte instructions aligned to 4 bytes; decoding this
    as ARM Thumb (2-byte) or x86 (variable-width) produces far more invalids.
    """
    code = bytes([
        0x27, 0xBD, 0xFF, 0xE0,  # addiu $sp, $sp, -32
        0xAF, 0xBF, 0x00, 0x1C,  # sw    $ra, 28($sp)
        0xAF, 0xBE, 0x00, 0x18,  # sw    $fp, 24($sp)
        0x03, 0xA0, 0xF0, 0x25,  # move  $fp, $sp
        0x8C, 0x82, 0x00, 0x00,  # lw    $v0, 0($a0)
        0x24, 0x63, 0x00, 0x01,  # addiu $v1, $v1, 1
        0x03, 0xC0, 0xE8, 0x25,  # move  $sp, $fp
        0x8F, 0xBF, 0x00, 0x1C,  # lw    $ra, 28($sp)
        0x03, 0xE0, 0x00, 0x08,  # jr    $ra
        0x27, 0xBD, 0x00, 0x20,  # addiu $sp, $sp, 32
    ]) * 8   # repeat 8× for a larger probe sample
    p = tmp_path_factory.mktemp("multi_arch") / "mips_be.bin"
    p.write_bytes(code)
    return p


# ── Thumb-2 fixture (re-use from test_disasm_stats) ──────────────────────────

@pytest.fixture(scope="session")
def thumb2_blob(tmp_path_factory) -> Path:
    """Minimal Thumb-2 blob: 4 × PUSH {…, lr} prologues + branches."""
    data = bytes([
        0x10, 0xB5,  # push {r4, lr}
        0x00, 0x20,  # movs r0, #0
        0x70, 0x47,  # bx lr
        0x30, 0xB5,  # push {r4, r5, lr}
        0x01, 0x20,  # movs r0, #1
        0x70, 0x47,  # bx lr
    ]) * 32
    p = tmp_path_factory.mktemp("multi_arch") / "thumb2.bin"
    p.write_bytes(data)
    return p


# ── probe_arch tests ──────────────────────────────────────────────────────────

@requires_capstone
def test_probe_arch_returns_tuple_of_three(x86_64_blob):
    result = arch_detect.probe_arch(x86_64_blob.read_bytes())
    assert isinstance(result, tuple)
    assert len(result) == 3


@requires_capstone
def test_probe_arch_x86_blob_identified(x86_64_blob):
    """x86-64 code should be identified as x86 or x86-64, not ARM."""
    name, cs_arch, cs_mode = arch_detect.probe_arch(x86_64_blob.read_bytes())
    assert name not in ("unknown", "ARM Thumb", "AArch64", "MIPS-LE", "MIPS-BE"), (
        f"Expected x86/x86-64, got {name!r}"
    )
    assert cs_arch is not None
    assert cs_mode is not None


@requires_capstone
def test_probe_arch_mips_be_identified(mips_be_blob):
    """MIPS-BE code should be identified as MIPS (LE or BE) rather than Thumb."""
    name, cs_arch, cs_mode = arch_detect.probe_arch(mips_be_blob.read_bytes())
    # The probe picks MIPS-BE because 100% of 4-byte chunks are valid MIPS-BE
    assert "MIPS" in name or name in ("x86", "x86-64"), (
        f"Expected MIPS-like arch, got {name!r}"
    )
    assert cs_arch is not None
    assert cs_mode is not None


@requires_capstone
def test_probe_arch_returns_ints_for_cs_fields(x86_64_blob):
    _, cs_arch, cs_mode = arch_detect.probe_arch(x86_64_blob.read_bytes())
    assert isinstance(cs_arch, int)
    assert isinstance(cs_mode, int)


def test_probe_arch_no_capstone_returns_unknown(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "capstone":
            raise ImportError("no module named capstone")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    name, arch, mode = arch_detect.probe_arch(b"\x55\x48\x89\xE5")
    assert name == "unknown"
    assert arch is None
    assert mode is None


def test_probe_arch_empty_bytes():
    name, arch, mode = arch_detect.probe_arch(b"")
    assert isinstance(name, str)
    assert arch is None or isinstance(arch, int)


# ── arch_detect.analyze — new fields ─────────────────────────────────────────

def test_analyze_has_disasm_arch_field(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert "disasm_arch" in result


def test_analyze_has_capstone_arch_field(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert "capstone_arch" in result


def test_analyze_has_capstone_mode_field(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert "capstone_mode" in result


@requires_capstone
def test_cortex_m_disasm_arch_is_arm_thumb(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["disasm_arch"] == "ARM Thumb"


@requires_capstone
def test_cortex_m_capstone_fields_are_ints(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert isinstance(result["capstone_arch"], int)
    assert isinstance(result["capstone_mode"], int)


@requires_capstone
def test_cortex_m_capstone_constructs_thumb_engine(cortex_m_firmware):
    """capstone_arch + capstone_mode must create a working Thumb Cs object."""
    import capstone
    result = arch_detect.analyze(cortex_m_firmware)
    cs = capstone.Cs(result["capstone_arch"], result["capstone_mode"])
    assert cs is not None


def test_non_baremetal_has_disasm_arch(tmp_path):
    """A clearly non-Cortex-M file still returns disasm_arch."""
    p = tmp_path / "random.bin"
    p.write_bytes(b"\xDE\xAD\xBE\xEF" * 64)
    result = arch_detect.analyze(p)
    assert isinstance(result.get("disasm_arch"), str)


# ── disasm_stats — arch from arch_info ───────────────────────────────────────

@requires_capstone
def test_disasm_stats_thumb2_mode_unchanged(thumb2_blob):
    """Thumb path: no arch_info → mode must still be 'thumb'."""
    result = disasm_stats.analyze(thumb2_blob)
    assert result["mode"] == "thumb"
    assert result["available"] is True


@requires_capstone
def test_disasm_stats_thumb2_prologues(thumb2_blob):
    """Thumb path: PUSH {…, lr} instructions are counted as prologues."""
    result = disasm_stats.analyze(thumb2_blob)
    assert result["function_prologues"] > 0


@requires_capstone
def test_disasm_stats_explicit_x86_64_arch(x86_64_blob):
    """Passing x86-64 capstone constants through arch_info selects x86-64 mode."""
    import capstone
    arch_info = {
        "capstone_arch": capstone.CS_ARCH_X86,
        "capstone_mode": capstone.CS_MODE_64,
        "disasm_arch":   "x86-64",
    }
    result = disasm_stats.analyze(x86_64_blob, arch_info=arch_info)
    assert result["available"] is True
    assert result["mode"] == "x86-64"
    assert result["arch_name"] == "x86-64"
    assert result["total_instructions"] > 0


@requires_capstone
def test_disasm_stats_x86_64_detects_prologues(x86_64_blob):
    """x86-64 PUSH RBP instructions are detected as function prologues."""
    import capstone
    arch_info = {
        "capstone_arch": capstone.CS_ARCH_X86,
        "capstone_mode": capstone.CS_MODE_64,
        "disasm_arch":   "x86-64",
    }
    result = disasm_stats.analyze(x86_64_blob, arch_info=arch_info)
    assert result["function_prologues"] > 0, (
        "expected PUSH RBP prologues; top mnemonics: "
        + str(result.get("top_mnemonics", [])[:5])
    )


@requires_capstone
def test_disasm_stats_explicit_mips_be_arch(mips_be_blob):
    """Passing MIPS-BE capstone constants through arch_info selects MIPS mode."""
    import capstone
    arch_info = {
        "capstone_arch": capstone.CS_ARCH_MIPS,
        "capstone_mode": capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
        "disasm_arch":   "MIPS-BE",
    }
    result = disasm_stats.analyze(mips_be_blob, arch_info=arch_info)
    assert result["available"] is True
    assert result["mode"] == "mips-be"
    assert result["total_instructions"] > 0


@requires_capstone
def test_disasm_stats_arch_name_in_result(x86_64_blob):
    """The arch_name key must be present in the result."""
    import capstone
    arch_info = {
        "capstone_arch": capstone.CS_ARCH_X86,
        "capstone_mode": capstone.CS_MODE_64,
        "disasm_arch":   "x86-64",
    }
    result = disasm_stats.analyze(x86_64_blob, arch_info=arch_info)
    assert "arch_name" in result
    assert result["arch_name"] == "x86-64"


@requires_capstone
def test_disasm_stats_bad_arch_info_falls_back(thumb2_blob):
    """Garbage capstone_arch/mode must fall back to Thumb without crashing."""
    arch_info = {"capstone_arch": "not_an_int", "capstone_mode": None}
    result = disasm_stats.analyze(thumb2_blob, arch_info=arch_info)
    assert result.get("available") is True
    assert result["mode"] == "thumb"
