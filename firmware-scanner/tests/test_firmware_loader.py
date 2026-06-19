"""Tests for firmware_loader — Intel HEX / SREC / UF2 normalisation."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from firmware_scanner import firmware_loader


# ── bincopy availability marker ───────────────────────────────────────────────

def _bincopy_available() -> bool:
    try:
        import bincopy  # noqa: F401
        return True
    except ImportError:
        return False


requires_bincopy = pytest.mark.skipif(
    not _bincopy_available(), reason="bincopy not installed"
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_uf2(address: int, payload: bytes) -> bytes:
    """Construct a minimal UF2 file with a single data block."""
    MAGIC1 = 0x0A324655
    MAGIC2 = 0x9E5D5157
    MAGIC3 = 0x0AB16F30
    block = bytearray(512)
    struct.pack_into("<I", block,   0, MAGIC1)
    struct.pack_into("<I", block,   4, MAGIC2)
    struct.pack_into("<I", block,   8, 0)            # flags
    struct.pack_into("<I", block,  12, address)
    struct.pack_into("<I", block,  16, len(payload))
    struct.pack_into("<I", block,  20, 0)            # block number
    struct.pack_into("<I", block,  24, 1)            # total blocks
    struct.pack_into("<I", block,  28, 0)            # family ID
    block[32: 32 + len(payload)] = payload
    struct.pack_into("<I", block, 508, MAGIC3)
    return bytes(block)


# ── detect format ─────────────────────────────────────────────────────────────

def test_detect_raw_by_extension(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(b"\x00" * 8)
    assert not firmware_loader.is_convertible(p)


def test_detect_hex_by_extension(tmp_path):
    p = tmp_path / "fw.hex"
    p.write_bytes(b":00000001FF\n")
    assert firmware_loader.is_convertible(p)


def test_detect_srec_by_extension(tmp_path):
    p = tmp_path / "fw.srec"
    p.write_bytes(b"S0030000FC\n")
    assert firmware_loader.is_convertible(p)


def test_detect_uf2_by_extension(tmp_path):
    p = tmp_path / "fw.uf2"
    p.write_bytes(_make_uf2(0x08000000, b"\xAA" * 16))
    assert firmware_loader.is_convertible(p)


# ── raw binary pass-through ───────────────────────────────────────────────────

def test_raw_binary_passthrough(tmp_path):
    data = bytes(range(64))
    p = tmp_path / "fw.bin"
    p.write_bytes(data)

    info = firmware_loader.load(p)

    assert info.format_name == "raw"
    assert info.raw_bytes == data
    assert info.load_address == 0
    assert info.size == 64


# ── Intel HEX round-trip ──────────────────────────────────────────────────────

@requires_bincopy
def test_ihex_round_trip(tmp_path):
    """Intel HEX → raw bytes round-trip preserves content and base address."""
    import bincopy

    LOAD_ADDR = 0x08000000
    data = bytes(range(256))

    bf = bincopy.BinFile()
    bf.add_binary(data, address=LOAD_ADDR)
    hex_path = tmp_path / "fw.hex"
    hex_path.write_text(bf.as_ihex(), encoding="ascii")

    info = firmware_loader.load(hex_path)

    assert info.format_name == "ihex"
    assert info.load_address == LOAD_ADDR
    assert info.raw_bytes == data
    assert info.size == len(data)


@requires_bincopy
def test_ihex_extracts_load_address(tmp_path):
    """Non-zero load address is returned from HEX records."""
    import bincopy

    LOAD_ADDR = 0x20000000  # SRAM base
    bf = bincopy.BinFile()
    bf.add_binary(b"\xDE\xAD\xBE\xEF", address=LOAD_ADDR)
    p = tmp_path / "sram.hex"
    p.write_text(bf.as_ihex(), encoding="ascii")

    info = firmware_loader.load(p)

    assert info.load_address == LOAD_ADDR


# ── Motorola SREC round-trip ──────────────────────────────────────────────────

@requires_bincopy
def test_srec_round_trip(tmp_path):
    """SREC → raw bytes round-trip preserves content and base address."""
    import bincopy

    LOAD_ADDR = 0x08001000
    data = b"Hello from SREC!" * 4

    bf = bincopy.BinFile()
    bf.add_binary(data, address=LOAD_ADDR)
    srec_path = tmp_path / "fw.srec"
    srec_path.write_text(bf.as_srec(), encoding="ascii")

    info = firmware_loader.load(srec_path)

    assert info.format_name == "srec"
    assert info.load_address == LOAD_ADDR
    assert info.raw_bytes == data
    assert info.size == len(data)


@requires_bincopy
def test_srec_s19_extension(tmp_path):
    """Files with .s19 extension are treated as SREC."""
    import bincopy

    bf = bincopy.BinFile()
    bf.add_binary(b"\xCA\xFE", address=0x08000000)
    p = tmp_path / "fw.s19"
    p.write_text(bf.as_srec(), encoding="ascii")

    info = firmware_loader.load(p)
    assert info.format_name == "srec"


# ── UF2 round-trip ───────────────────────────────────────────────────────────

def test_uf2_round_trip(tmp_path):
    """UF2 → raw bytes round-trip preserves content and base address."""
    LOAD_ADDR = 0x08000000
    payload   = b"\xAA\xBB\xCC\xDD" * 64  # 256 bytes

    p = tmp_path / "fw.uf2"
    p.write_bytes(_make_uf2(LOAD_ADDR, payload))

    info = firmware_loader.load(p)

    assert info.format_name == "uf2"
    assert info.load_address == LOAD_ADDR
    assert info.raw_bytes == payload
    assert info.size == len(payload)


def test_uf2_skips_noflash_blocks(tmp_path):
    """Blocks with NO_FLASH flag (0x1) are excluded from the output."""
    MAGIC1 = 0x0A324655
    MAGIC2 = 0x9E5D5157
    MAGIC3 = 0x0AB16F30
    FLAG_NOFLASH = 0x00000001

    # Block 0: normal data at 0x08000000
    blk0 = bytearray(512)
    struct.pack_into("<I", blk0,  0, MAGIC1)
    struct.pack_into("<I", blk0,  4, MAGIC2)
    struct.pack_into("<I", blk0,  8, 0)           # no flags
    struct.pack_into("<I", blk0, 12, 0x08000000)
    struct.pack_into("<I", blk0, 16, 4)
    struct.pack_into("<I", blk0, 20, 0)
    struct.pack_into("<I", blk0, 24, 2)
    blk0[32:36] = b"\xDE\xAD\xBE\xEF"
    struct.pack_into("<I", blk0, 508, MAGIC3)

    # Block 1: NO_FLASH (should be skipped)
    blk1 = bytearray(512)
    struct.pack_into("<I", blk1,  0, MAGIC1)
    struct.pack_into("<I", blk1,  4, MAGIC2)
    struct.pack_into("<I", blk1,  8, FLAG_NOFLASH)
    struct.pack_into("<I", blk1, 12, 0x08001000)
    struct.pack_into("<I", blk1, 16, 4)
    struct.pack_into("<I", blk1, 20, 1)
    struct.pack_into("<I", blk1, 24, 2)
    blk1[32:36] = b"\xFF\xFF\xFF\xFF"
    struct.pack_into("<I", blk1, 508, MAGIC3)

    p = tmp_path / "mixed.uf2"
    p.write_bytes(bytes(blk0) + bytes(blk1))

    info = firmware_loader.load(p)

    assert info.load_address == 0x08000000
    assert info.raw_bytes == b"\xDE\xAD\xBE\xEF"


def test_uf2_invalid_raises(tmp_path):
    """A completely invalid file raises RuntimeError."""
    p = tmp_path / "bad.uf2"
    p.write_bytes(b"\x00" * 512)

    with pytest.raises(RuntimeError):
        firmware_loader.load(p)


# ── FirmwareInfo is a NamedTuple ──────────────────────────────────────────────

def test_firmware_info_fields(tmp_path):
    p = tmp_path / "small.bin"
    p.write_bytes(b"\xAB" * 16)
    info = firmware_loader.load(p)

    assert hasattr(info, "raw_bytes")
    assert hasattr(info, "load_address")
    assert hasattr(info, "format_name")
    assert hasattr(info, "size")
