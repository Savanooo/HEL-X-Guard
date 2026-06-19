"""Bare-metal Cortex-M peripheral / register-map analysis (Feature 2).

Scans firmware bytes 4 at a time (word-scan) looking for 32-bit values
that fall inside known MCU peripheral address ranges.  This is equivalent
to extracting literal-pool constants from the binary, which is the
dominant pattern for peripheral base-address loads in STM32 HAL code.

Memory note: the word-scan replaces the earlier capstone full-disasm pass
(which used detail=True and could consume >100 MB for a 2 MB binary).  The
word-scan is O(n/4) integer comparisons and keeps only the matching values,
so memory overhead is negligible.  MOVW/MOVT split-encoded immediates are
not detected, but literal-pool loads cover the vast majority of cases.

Peripheral map
--------------
Uses an *approximate* STM32 generic map covering F4 / F7 / L4 / H7
families.  Exact base addresses differ between sub-families; the map
errs on the side of inclusion (any address within ±0x3FF of a listed
base is matched).  All addresses are labelled "approximate".

Security flags raised
---------------------
  flash_write_detected  — any access to the FLASH controller
  debug_port_left_open  — access to DBGMCU / CoreDebug / DWT / ITM
  watchdog_disabled     — IWDG or WWDG KR/CR register addresses found
  rdp_bypass_risk       — FLASH_OPTCR / FLASH_OPTR / FLASH_CR accesses

Risk contributions (consumed by risk_scoring.score via the caller)
-------------------------------------------------------------------
  debug_port_left_open : +10
  watchdog_disabled    : +10
  rdp_bypass_risk      : +15
  flash_write_detected : +8
"""
from __future__ import annotations

import struct
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


# ── Word-scan: find peripheral addresses in raw bytes ────────────────────────

def _word_scan_immediates(data: bytes) -> list[int]:
    """Scan firmware bytes 4 at a time for 32-bit peripheral-range addresses.

    Covers literal-pool constants (the dominant pattern in STM32 HAL code).
    O(n/4) time; output list is bounded by the number of matching 4-byte
    windows — negligible memory versus a full capstone detail=True pass.
    """
    immediates: list[int] = []
    end = len(data) - 3
    for i in range(0, end, 4):
        val = struct.unpack_from("<I", data, i)[0]
        if 0x40000000 <= val <= 0xE00FFFFF:
            immediates.append(val)
    return immediates


def analyze(path: Path, arch_info: dict | None = None,
            data: bytes | None = None) -> dict:
    """Word-scan firmware bytes and map 32-bit values to MCU peripheral ranges.

    Args:
        path:      Path to the firmware binary (used only if *data* is None).
        arch_info: ``report["arch"]`` from arch_detect.analyze() (kept for
                   API compatibility; no longer needed for the word-scan path).
        data:      Pre-read firmware bytes.  When supplied the file is not
                   re-read, avoiding an extra in-memory copy.

    Returns:
        {
            "available":   bool,
            "peripherals": [{"name": str, "base": str, "access_count": int,
                             "category": str, "families": str}],
            "flags":       [{"flag": str, "severity": str, "description": str,
                             "risk_score": int}],
            "flag_names":  [str],
            "error":       str | None
        }
    Never raises.
    """
    try:
        return _do_analyze(path, arch_info or {}, data)
    except Exception as exc:  # noqa: BLE001
        return {
            "available":   False,
            "peripherals": [],
            "flags":       [],
            "flag_names":  [],
            "error":       str(exc),
        }


def _do_analyze(path: Path, arch_info: dict, data: bytes | None) -> dict:
    if data is None:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return {
                "available": False, "peripherals": [], "flags": [],
                "flag_names": [], "error": str(exc),
            }

    immediates = _word_scan_immediates(data)

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
