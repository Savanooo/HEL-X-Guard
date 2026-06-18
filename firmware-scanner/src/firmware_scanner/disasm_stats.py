"""Instruction histogram and function-prologue estimate using capstone.

Tier 2 opt-in analysis — Thumb-2 linear sweep with ``skipdata=True`` so the
sweep covers the whole binary instead of stopping at the first data gap.

Design decisions
----------------
* **Always Thumb mode** — Cortex-M is Thumb-2 only.  Passing a different arch
  string is silently ignored; the module is hard-wired to
  ``Cs(CS_ARCH_ARM, CS_MODE_THUMB)``.
* **skipdata=True** — capstone emits a ``.byte`` placeholder for any 2-byte
  sequence it cannot decode cleanly.  Those placeholders are filtered out and
  never counted.
* **No per-instruction lists** — storing a list of 200 k+ instruction objects
  in the DB column would be huge.  Only aggregates are returned.
* **Mnemonic normalisation** — width suffixes (``.w``/``.n``) and conditional
  suffixes (``eq``/``ne``/…) are stripped so ``ldr.w`` and ``ldr`` both count
  as ``ldr``, and ``beq``/``bne`` both count as ``b``.
* **function_prologues** — count of ``PUSH {…, lr}`` instructions, the
  canonical Thumb-2 function-entry pattern.  Labelled as an *approximate*
  estimate because a linear sweep cannot perfectly separate code from data.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

_TOP_N         = 25
_DEFAULT_BASE  = 0x0800_0000   # STM32 flash default

_BRANCH_BASES = frozenset({
    "b", "bl", "bx", "blx", "cbz", "cbnz", "tbb", "tbh",
})
_MEMORY_BASES = frozenset({
    "ldr", "str", "ldm", "stm",
    "ldrb", "strb", "ldrh", "strh", "ldrd", "strd",
    "push", "pop", "vpush", "vpop",
})
_SUSPICIOUS = frozenset({"bkpt", "svc", "udf"})

_WIDTH_RE   = re.compile(r"\.(w|n)$")
_COND_CODES = frozenset({
    "eq", "ne", "cs", "hs", "cc", "lo",
    "mi", "pl", "vs", "vc", "hi", "ls",
    "ge", "lt", "gt", "le",
})


def _norm(mn: str) -> str:
    """Strip .w/.n width suffixes and collapse conditional branch variants.

    Examples:
        "ldr.w"  → "ldr"
        "str.n"  → "str"
        "beq"    → "b"
        "bleq"   → "bl"
        "bx"     → "bx"   (unchanged — no condition code)
    """
    mn = _WIDTH_RE.sub("", mn)
    if len(mn) >= 3 and mn[0] == "b":
        suffix = mn[-2:]
        if suffix in _COND_CODES:
            base = mn[:-2]
            if base in ("b", "bl"):
                return base
    return mn


def analyze(path: Path, arch_info: dict | None = None) -> dict:
    """Disassemble firmware in Thumb mode and compute instruction statistics.

    Args:
        path:      Path to firmware binary.
        arch_info: ``report_json["arch"]`` dict; used to extract
                   ``inferred_load_address`` (a hex string like ``"0x8000000"``).
                   Falls back to 0x08000000 if absent or unparseable.

    Returns:
        {
            "available":           bool,
            "mode":                "thumb",
            "load_address":        str,    # hex string, e.g. "0x8000000"
            "code_bytes":          int,
            "total_instructions":  int,
            "function_prologues":  int,    # PUSH {…, lr} count — approximate
            "branch_instructions": int,
            "memory_instructions": int,
            "suspicious":          {"bkpt": int, "svc": int, "udf": int},
            "top_mnemonics":       [{"mnemonic": str, "count": int}, ...],
            "error":               str | None,
        }

    On any failure returns ``{"available": False, "error": "<message>"}``.
    Never raises.
    """
    # ── capstone check ────────────────────────────────────────────────────────
    try:
        import capstone
    except ImportError:
        return {
            "available": False,
            "error": "capstone not installed — pip install capstone",
        }

    # ── resolve load address ──────────────────────────────────────────────────
    load_address = _DEFAULT_BASE
    if arch_info:
        raw = arch_info.get("inferred_load_address")
        if raw is not None:
            try:
                load_address = int(str(raw), 16)
            except (ValueError, TypeError):
                pass

    load_addr_hex = hex(load_address)

    # ── read binary ───────────────────────────────────────────────────────────
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"available": False, "error": str(exc)}

    code_bytes = len(data)

    # ── disassemble ───────────────────────────────────────────────────────────
    try:
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        md.detail   = False
        md.skipdata = True   # emit .byte placeholders instead of halting

        histogram: Counter[str] = Counter()
        function_prologues = 0
        branch_count       = 0
        memory_count       = 0
        suspicious_counts: dict[str, int] = {k: 0 for k in _SUSPICIOUS}

        for insn in md.disasm(data, load_address):
            raw_mn = insn.mnemonic.lower()

            # Skip .byte / .short / .long skipdata placeholders
            if raw_mn.startswith("."):
                continue

            mn = _norm(raw_mn)
            histogram[mn] += 1

            if mn in _SUSPICIOUS:
                suspicious_counts[mn] = suspicious_counts.get(mn, 0) + 1

            if mn in _BRANCH_BASES:
                branch_count += 1

            if mn in _MEMORY_BASES:
                memory_count += 1

            # Canonical Thumb-2 function entry: PUSH {…, lr}
            # capstone uses "lr" for r14 in Thumb mode; guard r14 too for safety
            if mn == "push" and ("lr" in insn.op_str or "r14" in insn.op_str):
                function_prologues += 1

        total = sum(histogram.values())
        top_mnemonics = [
            {"mnemonic": mn, "count": cnt}
            for mn, cnt in histogram.most_common(_TOP_N)
        ]

        return {
            "available":           True,
            "mode":                "thumb",
            "load_address":        load_addr_hex,
            "code_bytes":          code_bytes,
            "total_instructions":  total,
            "function_prologues":  function_prologues,
            "branch_instructions": branch_count,
            "memory_instructions": memory_count,
            "suspicious":          suspicious_counts,
            "top_mnemonics":       top_mnemonics,
            "error":               None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}
