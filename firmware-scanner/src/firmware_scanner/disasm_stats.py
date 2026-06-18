"""Instruction histogram and function-prologue count using capstone.

Opt-in Tier 2 analysis — heavier than the main scan but still purely static.
Disassembles the binary in Thumb (default) or ARM mode and produces:
  - mnemonic histogram (top N)
  - suspicious instruction occurrences (BKPT, SVC, WFI, WFE)
  - cheap function-count estimate from PUSH {…, lr} prologues

The full histogram is stored in the DB column (capped at 80 entries);
function_count and suspicious_instructions go there too.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

_MAX_HISTOGRAM = 80    # top mnemonics to keep
_MAX_SUSPICIOUS = 100  # cap suspicious instruction list
_SUSPICIOUS_MNEMONICS = frozenset({"bkpt", "svc", "swi", "hlt", "wfi", "wfe", "dmb", "dsb"})


def analyze(
    path: Path,
    arch: str = "thumb",
    load_address: int = 0,
) -> dict:
    """Disassemble firmware and compute instruction statistics.

    Args:
        path: Path to firmware binary.
        arch: "thumb" (default for Cortex-M), "arm", "arm64", "x86", "x86_64".
        load_address: Virtual address for the first byte (for annotation only).

    Returns:
        {
            "histogram": {"mnemonic": count, ...},   # top _MAX_HISTOGRAM
            "total_instructions": int,
            "function_count": int,
            "suspicious_instructions": [{"mnemonic", "op_str", "address"}, ...],
            "arch_used": str,
            "error": str | None,
        }
    """
    try:
        import capstone
    except ImportError:
        return {
            "histogram": {}, "total_instructions": 0, "function_count": 0,
            "suspicious_instructions": [], "arch_used": arch,
            "error": "capstone not installed — install with: pip install capstone",
        }

    try:
        data = path.read_bytes()
    except OSError as exc:
        return {
            "histogram": {}, "total_instructions": 0, "function_count": 0,
            "suspicious_instructions": [], "arch_used": arch, "error": str(exc),
        }

    try:
        cs_arch, cs_mode = _resolve_arch(arch, capstone)
        cs = capstone.Cs(cs_arch, cs_mode)
        cs.detail = False

        histogram: Counter = Counter()
        suspicious: list[dict] = []
        function_count = 0

        for insn in cs.disasm(data, load_address):
            mn = insn.mnemonic.lower()
            histogram[mn] += 1

            if mn in _SUSPICIOUS_MNEMONICS and len(suspicious) < _MAX_SUSPICIOUS:
                suspicious.append({
                    "mnemonic": mn,
                    "op_str":   insn.op_str,
                    "address":  hex(insn.address),
                })

            # Count Thumb PUSH {… lr} or ARM STMDB sp!, {… lr} as function prologues
            if mn in ("push", "stmdb") and "lr" in insn.op_str:
                function_count += 1

        top = dict(histogram.most_common(_MAX_HISTOGRAM))

        return {
            "histogram":              top,
            "total_instructions":     sum(histogram.values()),
            "function_count":         function_count,
            "suspicious_instructions": suspicious,
            "arch_used":              arch,
            "error":                  None,
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "histogram": {}, "total_instructions": 0, "function_count": 0,
            "suspicious_instructions": [], "arch_used": arch, "error": str(exc),
        }


def _resolve_arch(arch: str, capstone) -> tuple:  # type: ignore[type-arg]
    mapping = {
        "thumb":   (capstone.CS_ARCH_ARM,   capstone.CS_MODE_THUMB),
        "arm":     (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
        "arm64":   (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "x86":     (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
        "x86_64":  (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
    }
    arch_lower = arch.lower().replace("cortex-m", "thumb").replace("arm cortex-m", "thumb")
    return mapping.get(arch_lower, mapping["thumb"])
