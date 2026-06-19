"""Normalize Intel HEX, Motorola S-Record, and UF2 firmware formats to raw bytes.

Uses the `bincopy` library for HEX and SREC; UF2 is parsed with a built-in
block reader that requires no extra dependencies.  Returns the flat binary
payload **and** the lowest load address present in the records so downstream
modules (arch_detect, capstone) can use the real base address.

The firmware is only *read* — it is never executed.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import NamedTuple

try:
    import bincopy as _bincopy
    _BINCOPY_AVAILABLE = True
except ImportError:
    _BINCOPY_AVAILABLE = False

# UF2 magic constants
_UF2_MAGIC1   = 0x0A324655  # "UF2\n"
_UF2_MAGIC2   = 0x9E5D5157
_UF2_MAGIC3   = 0x0AB16F30
_UF2_BLOCK    = 512
_UF2_PAYLOAD  = 256
_UF2_FLAG_NOFLASH = 0x00000001  # skip blocks with this flag


class FirmwareInfo(NamedTuple):
    raw_bytes:    bytes  # flat binary payload
    load_address: int    # lowest flash address from records (0 if unknown)
    format_name:  str    # "ihex" | "srec" | "uf2" | "raw"
    size:         int    # byte count of raw_bytes


def _detect_format(path: Path) -> str:
    """Return format string by extension then by file magic."""
    ext = path.suffix.lower()
    if ext == ".hex":
        return "ihex"
    if ext in {".srec", ".s19", ".s28", ".s37", ".mot"}:
        return "srec"
    if ext == ".uf2":
        return "uf2"

    # Peek at the first four bytes
    try:
        header = path.read_bytes()[:4]
    except OSError:
        return "raw"

    if header[:2] == b":0":
        return "ihex"
    if len(header) >= 2 and chr(header[0]) == "S" and chr(header[1]).isdigit():
        return "srec"
    if len(header) == 4 and struct.unpack_from("<I", header)[0] == _UF2_MAGIC1:
        return "uf2"

    return "raw"


def _parse_uf2(data: bytes) -> tuple[bytes, int]:
    """Parse a UF2 file and return (raw_binary, base_address).

    Assembles all data blocks in address order, padding gaps with 0xFF.
    Blocks with the NO_FLASH flag are skipped.
    """
    if len(data) % _UF2_BLOCK != 0:
        raise ValueError(
            f"UF2 file size {len(data)} is not a multiple of 512"
        )

    segments: dict[int, bytes] = {}

    for offset in range(0, len(data), _UF2_BLOCK):
        blk = data[offset: offset + _UF2_BLOCK]
        magic1, magic2 = struct.unpack_from("<II", blk, 0)
        if magic1 != _UF2_MAGIC1 or magic2 != _UF2_MAGIC2:
            continue  # not a valid UF2 block

        flags       = struct.unpack_from("<I", blk,  8)[0]
        target_addr = struct.unpack_from("<I", blk, 12)[0]
        payload_sz  = struct.unpack_from("<I", blk, 16)[0]

        if flags & _UF2_FLAG_NOFLASH:
            continue  # skip non-flash blocks (e.g., file-container blocks)

        payload_sz = min(payload_sz, _UF2_PAYLOAD)  # clamp to slot size
        segments[target_addr] = blk[32: 32 + payload_sz]

    if not segments:
        raise ValueError("No valid UF2 data blocks found")

    base_addr = min(segments)
    end_addr  = max(addr + len(payload) for addr, payload in segments.items())
    span      = end_addr - base_addr

    raw = bytearray(b"\xff" * span)
    for addr, payload in segments.items():
        off = addr - base_addr
        raw[off: off + len(payload)] = payload

    return bytes(raw), base_addr


def load(path: Path) -> FirmwareInfo:
    """Load firmware from *path*, normalizing HEX/SREC/UF2 to raw bytes.

    For raw binary files the load_address is 0 (unknown); callers should
    use arch_detect to infer it.

    Raises RuntimeError if the file cannot be parsed.
    Never executes the firmware — only reads it.
    """
    fmt = _detect_format(path)

    # ── Raw binary — pass through ──────────────────────────────────────────────
    if fmt == "raw":
        data = path.read_bytes()
        return FirmwareInfo(
            raw_bytes=data, load_address=0, format_name="raw", size=len(data)
        )

    # ── UF2 — built-in parser (no bincopy needed) ─────────────────────────────
    if fmt == "uf2":
        try:
            raw, base = _parse_uf2(path.read_bytes())
            return FirmwareInfo(
                raw_bytes=raw, load_address=base, format_name="uf2", size=len(raw)
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to parse UF2 firmware '{path.name}': {exc}"
            ) from exc

    # ── Intel HEX / SREC — require bincopy ────────────────────────────────────
    if not _BINCOPY_AVAILABLE:
        raise RuntimeError(
            "bincopy is required to parse Intel HEX / SREC files — "
            "pip install bincopy"
        )

    try:
        bf = _bincopy.BinFile()
        text = path.read_text(encoding="ascii", errors="replace")
        if fmt == "ihex":
            bf.add_ihex(text)
        elif fmt == "srec":
            bf.add_srec(text)

        if not bf.segments:
            raise ValueError("No data segments found in file")

        base_addr = bf.minimum_address
        raw       = bf.as_binary(padding=b"\xff")
        return FirmwareInfo(
            raw_bytes=raw, load_address=base_addr, format_name=fmt, size=len(raw)
        )

    except Exception as exc:
        raise RuntimeError(
            f"Failed to parse {fmt} firmware '{path.name}': {exc}"
        ) from exc


def is_convertible(path: Path) -> bool:
    """Return True if *path* needs normalization (is not already raw binary)."""
    return _detect_format(path) != "raw"
