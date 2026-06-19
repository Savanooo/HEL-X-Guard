"""Instruction histogram and function-prologue estimate using capstone.

Tier 2 opt-in analysis — linear sweep with ``skipdata=True`` so the sweep
covers the whole binary instead of stopping at the first data gap.

Multi-architecture support (Feature 1)
---------------------------------------
The arch/mode is taken from ``arch_info["capstone_arch"]`` /
``arch_info["capstone_mode"]`` (integers stored by arch_detect.analyze).
Falls back to ARM Thumb when those fields are absent, keeping full backward
compatibility with existing STM32/Cortex-M behaviour.

Design decisions
----------------
* **skipdata=True** — capstone emits a ``.byte`` placeholder for any
  sequence it cannot decode cleanly.  Placeholders are filtered and never
  counted.
* **No per-instruction lists** — only aggregates are returned.
* **Mnemonic normalisation** — applied only for ARM arches (strips .w/.n
  width suffixes, collapses conditional branches so beq/bne both count as
  b).  Non-ARM arches pass the raw mnemonic through unchanged.
* **function_prologues** — approximate estimate; detection is arch-specific
  (push {lr} for ARM/Thumb, push rbp/ebp for x86, stp x29,x30 for AArch64).
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

_TOP_N        = 25
_DEFAULT_BASE = 0x0800_0000  # STM32 flash default

# ── ARM / Thumb sets (unchanged from original) ────────────────────────────────

_BRANCH_BASES = frozenset({
    "b", "bl", "bx", "blx", "cbz", "cbnz", "tbb", "tbh",
})
_MEMORY_BASES = frozenset({
    "ldr", "str", "ldm", "stm",
    "ldrb", "strb", "ldrh", "strh", "ldrd", "strd",
    "push", "pop", "vpush", "vpop",
})
_SUSPICIOUS = frozenset({"bkpt", "svc", "udf"})

# ── x86 / x86-64 sets ────────────────────────────────────────────────────────

_X86_BRANCH_BASES = frozenset({
    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
    "call", "ret", "retn",
})
_X86_MEMORY_BASES = frozenset({
    "mov", "push", "pop", "lea", "movsx", "movzx", "movsxd",
    "xchg", "movs", "stos", "lods", "scas", "cmps", "xor",
})

# ── MIPS sets ─────────────────────────────────────────────────────────────────

_MIPS_BRANCH_BASES = frozenset({
    "j", "jal", "jr", "jalr",
    "beq", "bne", "bgtz", "bltz", "bgez", "blez",
    "bgezal", "bltzal", "beql", "bnel", "b",
})
_MIPS_MEMORY_BASES = frozenset({
    "lw", "sw", "lb", "sb", "lh", "sh", "ld", "sd",
    "lbu", "lhu", "ldc1", "sdc1", "lwc1", "swc1",
    "lwr", "lwl", "swr", "swl", "ll", "sc", "lwu",
})

# ── AArch64 sets ──────────────────────────────────────────────────────────────

_AARCH64_MEMORY_BASES = frozenset({
    "ldr", "str", "ldp", "stp", "ldrb", "strb", "ldrh", "strh",
    "ldrsb", "ldrsh", "ldrsw", "prfm",
})

# ── Mnemonic normalisation (ARM only) ────────────────────────────────────────

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
        "beq"    → "b"
        "bleq"   → "bl"
        "bx"     → "bx"   (unchanged)
    """
    mn = _WIDTH_RE.sub("", mn)
    if len(mn) >= 3 and mn[0] == "b":
        suffix = mn[-2:]
        if suffix in _COND_CODES:
            base = mn[:-2]
            if base in ("b", "bl"):
                return base
    return mn


# ── Arch-specific helpers ─────────────────────────────────────────────────────

def _mode_string(disasm_arch: str) -> str:
    """Map arch name to the short mode string stored in the result."""
    return {
        "ARM Thumb":  "thumb",
        "ARM":        "arm",
        "AArch64":    "aarch64",
        "MIPS-LE":    "mips-le",
        "MIPS-BE":    "mips-be",
        "x86":        "x86",
        "x86-64":     "x86-64",
        "RISC-V 32":  "riscv",
    }.get(disasm_arch, "thumb")


def _arch_branch_memory(disasm_arch: str) -> tuple[frozenset, frozenset]:
    """Return (branch_bases, memory_bases) for the given arch."""
    if disasm_arch in ("x86", "x86-64"):
        return _X86_BRANCH_BASES, _X86_MEMORY_BASES
    if disasm_arch.startswith("MIPS"):
        return _MIPS_BRANCH_BASES, _MIPS_MEMORY_BASES
    if disasm_arch == "AArch64":
        # Use prefix matching for conditional branches — handled inline
        return frozenset(), _AARCH64_MEMORY_BASES
    return _BRANCH_BASES, _MEMORY_BASES  # ARM / Thumb default


def _is_branch(mn: str, disasm_arch: str, branch_bases: frozenset) -> bool:
    """Arch-aware branch instruction check."""
    if disasm_arch == "AArch64":
        # b, bl, br, blr, ret, b.cond, cbz, cbnz, tbz, tbnz
        return (mn.startswith("b") or mn in ("ret", "cbz", "cbnz", "tbz", "tbnz"))
    return mn in branch_bases


def _is_prologue(mn: str, op_str: str, disasm_arch: str) -> bool:
    """Return True when the instruction looks like a function entry point."""
    if disasm_arch in ("ARM Thumb", "ARM"):
        return mn == "push" and ("lr" in op_str or "r14" in op_str)
    if disasm_arch in ("x86", "x86-64"):
        return mn == "push" and ("rbp" in op_str or "ebp" in op_str)
    if disasm_arch == "AArch64":
        # stp x29, x30, [sp, #-N]!  — saves frame pointer + link register
        return mn == "stp" and "x29" in op_str and "x30" in op_str
    # MIPS: no reliable single-instruction prologue pattern
    return False


# ── Main analysis function ────────────────────────────────────────────────────

def analyze(path: Path, arch_info: dict | None = None) -> dict:
    """Disassemble firmware and compute instruction statistics.

    Args:
        path:      Path to firmware binary.
        arch_info: ``report_json["arch"]`` dict; used to extract
                   ``inferred_load_address``, ``capstone_arch``,
                   ``capstone_mode``, and ``disasm_arch``.
                   Falls back to ARM Thumb + 0x08000000 when absent.

    Returns a dict with keys:
        available, mode, arch_name, load_address, code_bytes,
        total_instructions, function_prologues, branch_instructions,
        memory_instructions, suspicious, top_mnemonics, error.

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

    # ── resolve arch / mode from arch_info ───────────────────────────────────
    cap_arch:     int    = capstone.CS_ARCH_ARM
    cap_mode:     int    = capstone.CS_MODE_THUMB
    disasm_arch:  str    = "ARM Thumb"

    if arch_info:
        raw_cap_arch = arch_info.get("capstone_arch")
        raw_cap_mode = arch_info.get("capstone_mode")
        raw_da       = arch_info.get("disasm_arch")
        if raw_cap_arch is not None and raw_cap_mode is not None:
            try:
                cap_arch    = int(raw_cap_arch)
                cap_mode    = int(raw_cap_mode)
                disasm_arch = str(raw_da) if raw_da else "ARM Thumb"
            except (TypeError, ValueError):
                pass  # keep Thumb defaults

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
        md          = capstone.Cs(cap_arch, cap_mode)
        md.detail   = False
        md.skipdata = True

        use_arm_norm          = disasm_arch in ("ARM Thumb", "ARM")
        branch_bases, mem_bases = _arch_branch_memory(disasm_arch)

        histogram: Counter[str] = Counter()
        function_prologues  = 0
        branch_count        = 0
        memory_count        = 0
        suspicious_counts: dict[str, int] = {k: 0 for k in _SUSPICIOUS}

        for insn in md.disasm(data, load_address):
            raw_mn = insn.mnemonic.lower()

            # Skip .byte / .short / .long skipdata placeholders
            if raw_mn.startswith("."):
                continue

            mn = _norm(raw_mn) if use_arm_norm else raw_mn
            histogram[mn] += 1

            if mn in _SUSPICIOUS:
                suspicious_counts[mn] = suspicious_counts.get(mn, 0) + 1

            if _is_branch(mn, disasm_arch, branch_bases):
                branch_count += 1

            if mn in mem_bases:
                memory_count += 1

            if _is_prologue(mn, insn.op_str, disasm_arch):
                function_prologues += 1

        total = sum(histogram.values())
        top_mnemonics = [
            {"mnemonic": mn, "count": cnt}
            for mn, cnt in histogram.most_common(_TOP_N)
        ]

        return {
            "available":           True,
            "mode":                _mode_string(disasm_arch),
            "arch_name":           disasm_arch,
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
