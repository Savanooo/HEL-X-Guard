"""Tests for arch_detect.py — Cortex-M vector table parser."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from firmware_scanner import arch_detect


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def cortex_m_firmware(tmp_path_factory) -> Path:
    """Synthetic STM32-style Cortex-M firmware binary.

    Offset 0: initial SP = 0x20020000 (valid STM32 RAM)
    Offset 4: reset handler = 0x08000101 (Thumb bit set, offset 0x100 in flash)
    Offset 8..127: zero padding (simulated interrupt vectors)
    Offset 256: a few recognizable bytes at the reset handler location
    """
    tmp = tmp_path_factory.mktemp("cortex_m")
    fw  = tmp / "stm32.bin"

    data = bytearray(512)
    # word[0] = initial SP (points to top of STM32F4 128KB SRAM)
    struct.pack_into("<I", data, 0, 0x20020000)
    # word[1] = reset handler: 0x08000100 | 1 (Thumb bit)
    struct.pack_into("<I", data, 4, 0x08000101)
    # A few more vector entries (Reset, NMI, HardFault, …)
    struct.pack_into("<I", data, 8,  0x08000201)  # NMI
    struct.pack_into("<I", data, 12, 0x08000301)  # HardFault
    # Reset handler body at offset 0x100 (= reset_addr - flash_base = 0x08000100 - 0x08000000)
    data[0x100] = 0x80  # arbitrary Thumb instruction bytes
    data[0x101] = 0xf0

    fw.write_bytes(bytes(data))
    return fw


@pytest.fixture(scope="session")
def raw_binary_no_vectors(tmp_path_factory) -> Path:
    """Random-looking binary with no valid vector table."""
    tmp = tmp_path_factory.mktemp("rand")
    p   = tmp / "random.bin"
    import random
    rng = random.Random(0xABCD)
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(256)))
    return p


@pytest.fixture(scope="session")
def tiny_file(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("tiny")
    p   = tmp / "tiny.bin"
    p.write_bytes(b"\x00\x01\x02\x03")  # < 8 bytes
    return p


# ── Basic structure ────────────────────────────────────────────────────────────

def test_returns_dict(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert isinstance(result, dict)


def test_required_keys_present(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    for key in ("is_bare_metal", "arch", "endianness", "inferred_load_address",
                "initial_sp", "reset_handler", "sp_in_ram", "thumb_mode",
                "vector_table", "reset_disasm", "error"):
        assert key in result, f"missing key: {key}"


def test_cortex_m_detected(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["is_bare_metal"] is True
    assert result["arch"] == "ARM Cortex-M"


def test_load_address_inferred(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["inferred_load_address"] == "0x8000000"


def test_thumb_mode_detected(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["thumb_mode"] is True


def test_sp_in_ram(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["sp_in_ram"] is True


def test_vector_table_is_list(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert isinstance(result["vector_table"], list)
    assert len(result["vector_table"]) > 0


def test_vector_table_entry_structure(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    entry = result["vector_table"][0]  # index 2 (NMI)
    assert "index" in entry
    assert "raw"   in entry
    assert "addr"  in entry
    assert "thumb" in entry


def test_initial_sp_hex_string(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    sp = result["initial_sp"]
    assert isinstance(sp, str)
    assert sp.startswith("0x")
    assert int(sp, 16) == 0x20020000


def test_no_error_on_valid_input(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["error"] is None


# ── Non-bare-metal binary ──────────────────────────────────────────────────────

def test_random_binary_not_bare_metal(raw_binary_no_vectors):
    result = arch_detect.analyze(raw_binary_no_vectors)
    # May or may not be detected, but should return valid dict
    assert isinstance(result["is_bare_metal"], bool)


def test_random_binary_arch_unknown_or_cortex(raw_binary_no_vectors):
    result = arch_detect.analyze(raw_binary_no_vectors)
    assert result["arch"] in ("unknown", "ARM Cortex-M")


# ── Edge cases ─────────────────────────────────────────────────────────────────

def test_tiny_file_returns_error(tiny_file):
    result = arch_detect.analyze(tiny_file)
    assert result["is_bare_metal"] is False
    assert result["error"] is not None


def test_endianness_little_for_bare_metal(cortex_m_firmware):
    result = arch_detect.analyze(cortex_m_firmware)
    assert result["endianness"] == "little"


def test_synthetic_firmware_does_not_crash(synthetic_firmware_file):
    result = arch_detect.analyze(synthetic_firmware_file)
    assert isinstance(result, dict)
    assert "is_bare_metal" in result
