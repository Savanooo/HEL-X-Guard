"""Cortex-M bare-metal architecture detection from raw binary.

Parses the ARM Cortex-M exception vector table at offset 0:
  word[0] = initial SP (must point into RAM)
  word[1] = reset handler address (bit 0 set = Thumb mode)

Never executes the binary — only reads bytes and disassembles statically.
"""
from __future__ import annotations

import struct
from pathlib import Path

# Common STM32 / ARM flash load bases
_FLASH_BASES = [
    0x08000000,  # STM32 internal flash (most common)
    0x00000000,  # boot ROM alias / Cortex-M0 devices
    0x10000000,  # ITCM alias (STM32H7)
    0x1FFF0000,  # STM32 system memory
    0x20000000,  # SRAM execute (bootloaders)
]

# Typical Cortex-M SRAM ranges (lo, hi inclusive)
_RAM_RANGES = [
    (0x20000000, 0x200FFFFF),  # STM32 SRAM
    (0x10000000, 0x1000FFFF),  # DTCM (STM32H7)
    (0x2001C000, 0x2002FFFF),  # STM32F4 CCM
]

_MAX_VECTORS = 48   # parse up to 48 exception/IRQ vectors (index 2..49)
_DISASM_BYTES = 48  # bytes of reset handler to disassemble


def _sp_in_ram(sp: int) -> bool:
    return any(lo <= sp <= hi for lo, hi in _RAM_RANGES)


def _infer_load_base(reset_addr: int, file_size: int) -> int | None:
    """Return the flash base whose offset makes reset_addr land inside the file."""
    for base in _FLASH_BASES:
        offset = reset_addr - base
        if 4 <= offset < file_size:
            return base
    return None


def analyze(path: Path, *, load_address_override: int | None = None) -> dict:
    """Detect Cortex-M architecture by parsing the vector table.

    *load_address_override* — when provided (non-zero) it is used as the flash
    base instead of the heuristic list in *_FLASH_BASES*.  Pass the value
    extracted from Intel HEX / SREC records so the caller's known base takes
    precedence over inference.

    Returns a dict with keys: is_bare_metal, arch, endianness,
    inferred_load_address, initial_sp, reset_handler, sp_in_ram,
    thumb_mode, vector_table (list), reset_disasm (list), error.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"is_bare_metal": False, "arch": "unknown", "error": str(exc)}

    if len(data) < 8:
        return {
            "is_bare_metal": False,
            "arch": "unknown",
            "error": "File too small for vector table parse (< 8 bytes)",
        }

    try:
        initial_sp, reset_handler_raw = struct.unpack_from("<II", data, 0)

        thumb_mode  = bool(reset_handler_raw & 1)
        reset_addr  = reset_handler_raw & ~1

        # Use the caller-supplied load address if given (e.g. from HEX records);
        # otherwise infer from the known STM32/Cortex-M flash base list.
        if load_address_override:
            load_base = load_address_override
        else:
            load_base = _infer_load_base(reset_addr, len(data))
        is_bare_metal = load_base is not None
        sp_ok       = _sp_in_ram(initial_sp)

        # Parse interrupt/exception vector table entries (indices 2…N)
        n_entries = min(_MAX_VECTORS, (len(data) // 4) - 2)
        vectors = []
        for i in range(n_entries):
            raw = struct.unpack_from("<I", data, (i + 2) * 4)[0]
            vectors.append({
                "index": i + 2,
                "raw":   hex(raw),
                "addr":  hex(raw & ~1),
                "thumb": bool(raw & 1),
            })

        reset_disasm: list[str] = []
        if is_bare_metal and thumb_mode:
            offset = reset_addr - load_base
            if 0 <= offset <= len(data) - _DISASM_BYTES:
                reset_disasm = _disasm_thumb(data[offset: offset + _DISASM_BYTES], reset_addr)

        return {
            "is_bare_metal":         is_bare_metal,
            "arch":                  "ARM Cortex-M" if is_bare_metal else "unknown",
            "endianness":            "little" if is_bare_metal else "unknown",
            "inferred_load_address": hex(load_base) if load_base is not None else None,
            "initial_sp":            hex(initial_sp),
            "reset_handler":         hex(reset_handler_raw),
            "sp_in_ram":             sp_ok,
            "thumb_mode":            thumb_mode,
            "vector_table":          vectors,
            "reset_disasm":          reset_disasm,
            "error":                 None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"is_bare_metal": False, "arch": "unknown", "error": str(exc)}


def _disasm_thumb(code: bytes, start_addr: int) -> list[str]:
    """Disassemble Thumb code at start_addr; return up to 12 lines."""
    try:
        import capstone  # optional dependency

        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        cs.detail = False
        lines = []
        for insn in cs.disasm(code, start_addr):
            lines.append(f"0x{insn.address:08x}:  {insn.mnemonic:<8} {insn.op_str}")
            if len(lines) >= 12:
                break
        return lines
    except Exception:
        return []
