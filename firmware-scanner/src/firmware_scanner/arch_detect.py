"""Architecture detection from raw binary.

Primary path: Cortex-M bare-metal detection via ARM exception vector table
  word[0] = initial SP (must point into RAM)
  word[1] = reset handler address (bit 0 set = Thumb mode)

Secondary path: when not bare-metal, probe a sample of the binary against
all supported capstone architectures and pick the one with the fewest
.byte placeholder (invalid/undecodable) instructions.

Supported via capstone:
  ARM Thumb, ARM (A-profile), AArch64, MIPS-LE, MIPS-BE, x86, x86-64,
  RISC-V 32 (if capstone was compiled with RISC-V support).

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

_MAX_VECTORS    = 48    # parse up to 48 exception/IRQ vectors (index 2..49)
_DISASM_BYTES   = 48    # bytes of reset handler to disassemble
_PROBE_SAMPLE   = 4096  # bytes used for arch probing


def _sp_in_ram(sp: int) -> bool:
    return any(lo <= sp <= hi for lo, hi in _RAM_RANGES)


def _infer_load_base(reset_addr: int, file_size: int) -> int | None:
    """Return the flash base whose offset makes reset_addr land inside the file."""
    for base in _FLASH_BASES:
        offset = reset_addr - base
        if 4 <= offset < file_size:
            return base
    return None


# ── Multi-arch probing ────────────────────────────────────────────────────────

def probe_arch(data: bytes, sample_size: int = _PROBE_SAMPLE) -> tuple[str, int | None, int | None]:
    """Probe *data* to find the best-matching capstone architecture.

    Tries each arch/mode candidate on the first *sample_size* bytes and
    returns the one with the highest ratio of valid (non-placeholder)
    instructions.

    Returns:
        (disasm_arch_name, capstone_arch_int, capstone_mode_int)
        e.g. ("x86-64", 4, 8) or ("unknown", None, None) if capstone
        is not installed or no candidate scores above zero.

    Never raises.
    """
    try:
        import capstone as _cs
    except ImportError:
        return ("unknown", None, None)

    sample = data[:sample_size]
    if not sample:
        return ("unknown", None, None)

    candidates: list[tuple[str, int, int]] = [
        ("ARM Thumb",  _cs.CS_ARCH_ARM,   _cs.CS_MODE_THUMB),
        ("ARM",        _cs.CS_ARCH_ARM,   _cs.CS_MODE_ARM),
        ("AArch64",    _cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM),
        ("MIPS-LE",    _cs.CS_ARCH_MIPS,  _cs.CS_MODE_MIPS32 | _cs.CS_MODE_LITTLE_ENDIAN),
        ("MIPS-BE",    _cs.CS_ARCH_MIPS,  _cs.CS_MODE_MIPS32 | _cs.CS_MODE_BIG_ENDIAN),
        ("x86",        _cs.CS_ARCH_X86,   _cs.CS_MODE_32),
        ("x86-64",     _cs.CS_ARCH_X86,   _cs.CS_MODE_64),
    ]
    # Optional RISC-V (available in capstone ≥ 5.0 built with RISC-V support)
    _rv_arch = getattr(_cs, "CS_ARCH_RISCV", None)
    _rv_mode = getattr(_cs, "CS_MODE_RISCV32", None)
    if _rv_arch is not None and _rv_mode is not None:
        candidates.append(("RISC-V 32", _rv_arch, _rv_mode))

    best_name: str        = "unknown"
    best_arch: int | None = None
    best_mode: int | None = None
    best_ratio: float     = -1.0

    for name, arch, mode in candidates:
        try:
            md         = _cs.Cs(arch, mode)
            md.skipdata = True
            valid = invalid = 0
            for insn in md.disasm(sample, 0x0):
                if insn.mnemonic.startswith("."):
                    invalid += 1
                else:
                    valid += 1
            total = valid + invalid
            if total == 0:
                continue
            ratio = valid / total
            if ratio > best_ratio:
                best_ratio = ratio
                best_name  = name
                best_arch  = arch
                best_mode  = mode
        except Exception:  # noqa: BLE001
            continue

    return (best_name, best_arch, best_mode)


# ── Primary analysis ──────────────────────────────────────────────────────────

_PROBE_MAX = 65536   # cap multi-arch probe at first 64 KB


def analyze(path: Path, *, load_address_override: int | None = None,
            data: bytes | None = None) -> dict:
    """Detect architecture by parsing the ARM Cortex-M vector table.

    Falls back to probing all supported capstone arches when the binary
    does not look like bare-metal Cortex-M firmware.

    *load_address_override* — when provided (non-zero) it is used as the
    flash base instead of the heuristic list in *_FLASH_BASES*.

    *data* — pre-read firmware bytes.  When supplied the file is not
    re-read, avoiding an extra in-memory copy.

    Returns a dict with keys:
        is_bare_metal, arch, endianness, inferred_load_address,
        initial_sp, reset_handler, sp_in_ram, thumb_mode,
        vector_table (list), reset_disasm (list), error,
        disasm_arch (str), capstone_arch (int|None), capstone_mode (int|None)
    """
    if data is None:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return {
                "is_bare_metal": False, "arch": "unknown", "error": str(exc),
                "disasm_arch": "unknown", "capstone_arch": None, "capstone_mode": None,
            }

    if len(data) < 8:
        return {
            "is_bare_metal": False,
            "arch":          "unknown",
            "error":         "File too small for vector table parse (< 8 bytes)",
            "disasm_arch":   "unknown",
            "capstone_arch": None,
            "capstone_mode": None,
        }

    try:
        initial_sp, reset_handler_raw = struct.unpack_from("<II", data, 0)

        thumb_mode  = bool(reset_handler_raw & 1)
        reset_addr  = reset_handler_raw & ~1

        if load_address_override:
            load_base = load_address_override
        else:
            load_base = _infer_load_base(reset_addr, len(data))
        is_bare_metal = load_base is not None
        sp_ok         = _sp_in_ram(initial_sp)

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

        # ── Determine capstone arch/mode for downstream consumers ─────────
        if is_bare_metal:
            # Cortex-M detected — always Thumb-2 for Cortex-M0/M0+/M3/M4/M7/M33/M55
            disasm_arch, cap_arch, cap_mode = _cortex_m_cs(thumb_mode)
        else:
            # Limit probe to first 64 KB — avoids iterating capstone over the
            # entire binary × N arch candidates (memory and CPU savings).
            disasm_arch, cap_arch, cap_mode = probe_arch(data[:_PROBE_MAX])

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
            # New fields (Feature 1)
            "disasm_arch":           disasm_arch,
            "capstone_arch":         cap_arch,
            "capstone_mode":         cap_mode,
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "is_bare_metal": False, "arch": "unknown", "error": str(exc),
            "disasm_arch": "unknown", "capstone_arch": None, "capstone_mode": None,
        }


def _cortex_m_cs(thumb_mode: bool) -> tuple[str, int | None, int | None]:
    """Return (disasm_arch, capstone_arch, capstone_mode) for Cortex-M."""
    try:
        import capstone as _cs
        arch = _cs.CS_ARCH_ARM
        mode = _cs.CS_MODE_THUMB if thumb_mode else _cs.CS_MODE_ARM
        name = "ARM Thumb" if thumb_mode else "ARM"
        return (name, arch, mode)
    except ImportError:
        return ("ARM Thumb" if thumb_mode else "ARM", None, None)


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
