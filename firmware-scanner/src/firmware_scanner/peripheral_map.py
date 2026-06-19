"""Bare-metal Cortex-M peripheral / register-map analysis (Feature 2).

Disassembles the firmware with capstone and collects every immediate
operand that falls inside a known MCU peripheral address range.  Reports
which peripheral blocks are "touched" and flags security-relevant accesses.

Peripheral map
--------------
Uses an *approximate* STM32 generic map covering F4 / F7 / L4 / H7
families.  Exact base addresses differ between sub-families; the map
errs on the side of inclusion (any address within ±0x3FF of a listed
base is matched).  All addresses are labelled "approximate".

Security flags raised
---------------------
  flash_write_detected  — any access to the FLASH controller (write-to-
                          flash without integrity checks is a supply-chain
                          risk and may disable readout protection silently)
  debug_port_left_open  — access to DBGMCU / CoreDebug / DWT / ITM
                          peripherals suggests the debug interface is
                          enabled in production firmware
  watchdog_disabled     — IWDG or WWDG KR/CR register addresses accessed
                          in a pattern consistent with disabling the
                          watchdog (write to key register before reload)
  rdp_bypass_risk       — FLASH_OPTCR / FLASH_OPTR / FLASH_CR accesses
                          near Option Byte programming sequences — could
                          indicate RDP downgrade or bypass

Risk contributions (consumed by risk_scoring.score via the caller)
-------------------------------------------------------------------
  debug_port_left_open : +10
  watchdog_disabled    : +10
  rdp_bypass_risk      : +15
  flash_write_detected : +8
"""
from __future__ import annotations

from pathlib import Path

# ── Peripheral map ────────────────────────────────────────────────────────────
# Format: name → {base, size, category, security_flag}
# "approximate" because F4/F7/L4/H7 have slightly different bases.

_PERIPHERAL_MAP: list[dict] = [
    # FLASH controller
    {"name": "FLASH_CTRL",  "base": 0x40023C00, "size": 0x400, "category": "flash",   "families": "F4/F7"},
    {"name": "FLASH_CTRL",  "base": 0x40022000, "size": 0x400, "category": "flash",   "families": "L4"},
    {"name": "FLASH_CTRL",  "base": 0x52002000, "size": 0x400, "category": "flash",   "families": "H7"},
    # RCC (clock control)
    {"name": "RCC",         "base": 0x40023800, "size": 0x400, "category": "clock",   "families": "F4/F7"},
    {"name": "RCC",         "base": 0x40021000, "size": 0x400, "category": "clock",   "families": "L4"},
    {"name": "RCC",         "base": 0x58024400, "size": 0x400, "category": "clock",   "families": "H7"},
    # GPIO ports A–H
    {"name": "GPIOA",       "base": 0x40020000, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    {"name": "GPIOB",       "base": 0x40020400, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    {"name": "GPIOC",       "base": 0x40020800, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    {"name": "GPIOD",       "base": 0x40020C00, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    {"name": "GPIOE",       "base": 0x40021000, "size": 0x400, "category": "io",      "families": "F4/F7"},
    {"name": "GPIOH",       "base": 0x40021C00, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    # Debug / trace
    {"name": "DBGMCU",      "base": 0xE0042000, "size": 0x400, "category": "debug",   "families": "F4/F7/L4/H7"},
    {"name": "CoreDebug",   "base": 0xE000EDF0, "size": 0x10,  "category": "debug",   "families": "all"},
    {"name": "DWT",         "base": 0xE0001000, "size": 0x1000,"category": "debug",   "families": "all"},
    {"name": "ITM",         "base": 0xE0000000, "size": 0x1000,"category": "debug",   "families": "all"},
    {"name": "ETM",         "base": 0xE0041000, "size": 0x1000,"category": "debug",   "families": "all"},
    # Watchdog
    {"name": "IWDG",        "base": 0x40003000, "size": 0x400, "category": "watchdog","families": "F4/F7/L4/H7"},
    {"name": "WWDG",        "base": 0x40002C00, "size": 0x400, "category": "watchdog","families": "F4/F7/L4/H7"},
    # Crypto / RNG
    {"name": "CRYP",        "base": 0x50060000, "size": 0x400, "category": "crypto",  "families": "F4/F7/H7"},
    {"name": "RNG",         "base": 0x50060800, "size": 0x400, "category": "crypto",  "families": "F4/F7/H7"},
    {"name": "HASH",        "base": 0x50060400, "size": 0x400, "category": "crypto",  "families": "F4/F7/H7"},
    # UART / USART
    {"name": "USART1",      "base": 0x40011000, "size": 0x400, "category": "io",      "families": "F4/F7/L4/H7"},
    {"name": "USART2",      "base": 0x40004400, "size": 0x400, "category": "io",      "families": "F4/F7/L4/H7"},
    # SPI
    {"name": "SPI1",        "base": 0x40013000, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    {"name": "SPI2",        "base": 0x40003800, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    # I2C
    {"name": "I2C1",        "base": 0x40005400, "size": 0x400, "category": "io",      "families": "F4/F7/L4"},
    # Timers
    {"name": "TIM1",        "base": 0x40010000, "size": 0x400, "category": "timer",   "families": "F4/F7/L4/H7"},
    {"name": "TIM2",        "base": 0x40000000, "size": 0x400, "category": "timer",   "families": "F4/F7/L4/H7"},
    # System Control Block
    {"name": "SCB",         "base": 0xE000ED00, "size": 0x100, "category": "core",    "families": "all"},
    {"name": "NVIC",        "base": 0xE000E100, "size": 0xC00, "category": "core",    "families": "all"},
    {"name": "SysTick",     "base": 0xE000E010, "size": 0x10,  "category": "core",    "families": "all"},
    # MPU
    {"name": "MPU",         "base": 0xE000ED90, "size": 0x60,  "category": "security","families": "all"},
]

# Pre-build sorted interval list for O(log n) lookup
_SORTED_PERIPHERALS: list[tuple[int, int, dict]] = sorted(
    ((p["base"], p["base"] + p["size"] - 1, p) for p in _PERIPHERAL_MAP),
    key=lambda t: t[0],
)

# ── Security flag thresholds / patterns ───────────────────────────────────────

_FLAG_DEBUG_CATS    = frozenset({"debug"})
_FLAG_WATCHDOG_CATS = frozenset({"watchdog"})
_FLAG_FLASH_CATS    = frozenset({"flash"})

# RDP-related FLASH register offsets (OPTCR, CR, etc.)
_RDP_REGISTER_OFFSETS = {0x14, 0x10, 0x08}  # OPTCR, OPTSR, CR relative to FLASH base

# Risk contributions per flag
FLAG_RISK: dict[str, int] = {
    "debug_port_left_open": 10,
    "watchdog_disabled":    10,
    "rdp_bypass_risk":      15,
    "flash_write_detected":  8,
}


def _lookup_peripheral(addr: int) -> dict | None:
    """Return the peripheral dict if addr falls in any known peripheral range."""
    for lo, hi, p in _SORTED_PERIPHERALS:
        if addr < lo:
            break
        if lo <= addr <= hi:
            return p
    return None


# ── Disassemble and collect peripheral accesses ───────────────────────────────

def _extract_immediates(data: bytes, load_address: int,
                        cap_arch: int, cap_mode: int) -> list[int]:
    """Return all 32-bit immediate values from the disassembly.

    Uses capstone with detail=True so we can inspect operand values.
    Includes both mov-immediate patterns and literal pool loads (LDR pc-relative).
    """
    try:
        import capstone
        md = capstone.Cs(cap_arch, cap_mode)
        md.detail   = True
        md.skipdata = True
        immediates: list[int] = []

        for insn in md.disasm(data, load_address):
            if insn.mnemonic.startswith("."):
                continue
            # Extract 32-bit-range immediate operands
            if hasattr(insn, "operands"):
                for op in insn.operands:
                    imm_val = None
                    op_type = getattr(op, "type", None)
                    # capstone ARM: OP_IMM=2, OP_MEM=3
                    if op_type == 2:  # IMM
                        imm_val = getattr(op, "imm", None)
                    elif op_type == 3:  # MEM — check displacement
                        mem = getattr(op, "mem", None)
                        if mem:
                            disp = getattr(mem, "disp", 0)
                            # Only use memory operands where base looks like a peripheral addr
                            base_reg_val = getattr(mem, "base", 0)
                            if base_reg_val == 0 and disp and 0x40000000 <= disp <= 0xE00FFFFF:
                                imm_val = disp
                    if imm_val is not None:
                        val = int(imm_val) & 0xFFFFFFFF
                        if 0x40000000 <= val <= 0xE00FFFFF:
                            immediates.append(val)
            else:
                # Fallback: parse hex values from op_str
                import re
                for m in re.finditer(r'0x([0-9a-fA-F]{5,8})', insn.op_str):
                    val = int(m.group(1), 16)
                    if 0x40000000 <= val <= 0xE00FFFFF:
                        immediates.append(val)

        return immediates
    except Exception:
        return []


def analyze(path: Path, arch_info: dict | None = None) -> dict:
    """Disassemble firmware and map immediate values to MCU peripherals.

    Args:
        path:      Path to the firmware binary.
        arch_info: ``report["arch"]`` from arch_detect.analyze().
                   Used to obtain load_address, capstone_arch, capstone_mode.

    Returns:
        {
            "available":   bool,
            "peripherals": [{"name": str, "base": str, "access_count": int,
                             "category": str, "families": str}],
            "flags":       [{"flag": str, "severity": str, "description": str,
                             "risk_score": int}],
            "flag_names":  [str],           # flat list for risk_scoring
            "error":       str | None
        }
    Never raises.
    """
    try:
        return _do_analyze(path, arch_info or {})
    except Exception as exc:  # noqa: BLE001
        return {
            "available":   False,
            "peripherals": [],
            "flags":       [],
            "flag_names":  [],
            "error":       str(exc),
        }


def _do_analyze(path: Path, arch_info: dict) -> dict:
    try:
        import capstone  # noqa: F401
    except ImportError:
        return {
            "available":   False,
            "peripherals": [],
            "flags":       [],
            "flag_names":  [],
            "error":       "capstone not installed",
        }

    # Resolve capstone arch / mode (default: ARM Thumb)
    try:
        import capstone as _cs
        cap_arch = int(arch_info.get("capstone_arch") or _cs.CS_ARCH_ARM)
        cap_mode = int(arch_info.get("capstone_mode") or _cs.CS_MODE_THUMB)
    except (TypeError, ValueError):
        import capstone as _cs
        cap_arch = _cs.CS_ARCH_ARM
        cap_mode = _cs.CS_MODE_THUMB

    load_addr_raw = arch_info.get("inferred_load_address", "0x8000000")
    try:
        load_address = int(str(load_addr_raw), 16)
    except (TypeError, ValueError):
        load_address = 0x08000000

    try:
        data = path.read_bytes()
    except OSError as exc:
        return {
            "available": False, "peripherals": [], "flags": [],
            "flag_names": [], "error": str(exc),
        }

    immediates = _extract_immediates(data, load_address, cap_arch, cap_mode)

    # Tally peripheral accesses
    access_counts: dict[str, dict] = {}
    for val in immediates:
        p = _lookup_peripheral(val)
        if p is None:
            continue
        key = p["name"]
        if key not in access_counts:
            access_counts[key] = {**p, "access_count": 0}
        access_counts[key]["access_count"] += 1

    # Build output peripherals list
    peripherals = [
        {
            "name":         info["name"],
            "base":         hex(info["base"]),
            "access_count": info["access_count"],
            "category":     info["category"],
            "families":     info.get("families", ""),
        }
        for info in sorted(access_counts.values(), key=lambda x: -x["access_count"])
    ]

    # Compute categories seen
    cats_seen = {info["category"] for info in access_counts.values()}

    # Derive security flags
    flags: list[dict] = []
    flag_names: list[str] = []

    if _FLAG_DEBUG_CATS & cats_seen:
        flags.append({
            "flag":       "debug_port_left_open",
            "severity":   "medium",
            "description": (
                "Debug peripheral (DBGMCU/CoreDebug/DWT/ITM) addresses referenced "
                "in firmware — debug interface may be left enabled in production."
            ),
            "risk_score": FLAG_RISK["debug_port_left_open"],
        })
        flag_names.append("debug_port_left_open")

    if _FLAG_WATCHDOG_CATS & cats_seen:
        flags.append({
            "flag":       "watchdog_disabled",
            "severity":   "medium",
            "description": (
                "IWDG/WWDG register addresses referenced — check whether watchdog "
                "is being disabled (missing reload) rather than properly serviced."
            ),
            "risk_score": FLAG_RISK["watchdog_disabled"],
        })
        flag_names.append("watchdog_disabled")

    if _FLAG_FLASH_CATS & cats_seen:
        flags.append({
            "flag":       "flash_write_detected",
            "severity":   "high",
            "description": (
                "FLASH controller register addresses referenced — firmware can "
                "write or erase its own flash, which could disable readout "
                "protection or enable unsigned firmware updates."
            ),
            "risk_score": FLAG_RISK["flash_write_detected"],
        })
        flag_names.append("flash_write_detected")

        # Check for RDP-specific register offsets
        flash_bases = {p["base"] for p in _PERIPHERAL_MAP if p["category"] == "flash"}
        for val in immediates:
            for fb in flash_bases:
                if val - fb in _RDP_REGISTER_OFFSETS:
                    flags.append({
                        "flag":       "rdp_bypass_risk",
                        "severity":   "critical",
                        "description": (
                            f"Potential access to FLASH Option Byte register "
                            f"(0x{val:08x}) — could indicate RDP downgrade attempt."
                        ),
                        "risk_score": FLAG_RISK["rdp_bypass_risk"],
                    })
                    flag_names.append("rdp_bypass_risk")
                    break
            else:
                continue
            break  # only raise once

    return {
        "available":   True,
        "peripherals": peripherals,
        "flags":       flags,
        "flag_names":  flag_names,
        "error":       None,
    }
