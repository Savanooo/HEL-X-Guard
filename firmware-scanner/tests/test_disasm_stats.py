"""Tests for disasm_stats.py — Thumb-2 instruction histogram with skipdata."""
from __future__ import annotations

from pathlib import Path

import pytest

from firmware_scanner import disasm_stats


# ── capstone availability ─────────────────────────────────────────────────────

def _capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


requires_capstone = pytest.mark.skipif(
    not _capstone_available(), reason="capstone not installed"
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def thumb2_firmware(tmp_path_factory) -> Path:
    """32 bytes of deterministic Thumb-2 instructions with exactly 4 prologues.

    Instruction layout (all 2-byte Thumb-16 encodings):
        0x10 0xB5  push {r4, lr}       ← prologue 1, memory
        0x00 0x20  movs r0, #0
        0x04 0x48  ldr  r0, [pc, #16]  ← memory
        0x70 0x47  bx   lr             ← branch
        0x30 0xB5  push {r4, r5, lr}   ← prologue 2, memory
        0x01 0x20  movs r0, #1
        0x04 0x48  ldr  r0, [pc, #16]  ← memory
        0x70 0x47  bx   lr             ← branch
        0xF0 0xB5  push {r4-r7, lr}    ← prologue 3, memory
        0x00 0xBF  nop
        0x70 0x47  bx   lr             ← branch
        0x70 0xB5  push {r4-r6, lr}    ← prologue 4, memory
        0x04 0x48  ldr  r0, [pc, #16]  ← memory
        0x70 0x47  bx   lr             ← branch

    Total: 14 instructions
      push: 4  (all with lr → all prologues)
      movs: 2
      ldr:  3
      nop:  1
      bx:   4  (all branch)
    """
    data = bytes([
        0x10, 0xB5,   # push {r4, lr}
        0x00, 0x20,   # movs r0, #0
        0x04, 0x48,   # ldr r0, [pc, #16]
        0x70, 0x47,   # bx lr
        0x30, 0xB5,   # push {r4, r5, lr}
        0x01, 0x20,   # movs r0, #1
        0x04, 0x48,   # ldr r0, [pc, #16]
        0x70, 0x47,   # bx lr
        0xF0, 0xB5,   # push {r4, r5, r6, r7, lr}
        0x00, 0xBF,   # nop
        0x70, 0x47,   # bx lr
        0x70, 0xB5,   # push {r4, r5, r6, lr}
        0x04, 0x48,   # ldr r0, [pc, #16]
        0x70, 0x47,   # bx lr
    ])
    p = tmp_path_factory.mktemp("disasm") / "thumb2.bin"
    p.write_bytes(data)
    return p


@pytest.fixture(scope="session")
def zero_firmware(tmp_path_factory) -> Path:
    """512 zero bytes — tests that skipdata handles undecodable regions."""
    p = tmp_path_factory.mktemp("disasm") / "zeros.bin"
    p.write_bytes(b"\x00" * 512)
    return p


# ── Return structure ──────────────────────────────────────────────────────────

@requires_capstone
def test_returns_dict(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware)
    assert isinstance(result, dict)


@requires_capstone
def test_available_true(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware)
    assert result.get("available") is True


@requires_capstone
def test_required_keys(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware)
    for key in (
        "available", "mode", "load_address", "code_bytes",
        "total_instructions", "function_prologues",
        "branch_instructions", "memory_instructions",
        "suspicious", "top_mnemonics", "error",
    ):
        assert key in result, f"missing key: {key}"


@requires_capstone
def test_mode_is_thumb(thumb2_firmware):
    assert disasm_stats.analyze(thumb2_firmware)["mode"] == "thumb"


@requires_capstone
def test_error_none_on_valid_input(thumb2_firmware):
    assert disasm_stats.analyze(thumb2_firmware)["error"] is None


@requires_capstone
def test_code_bytes_matches_file_size(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware)
    assert result["code_bytes"] == thumb2_firmware.stat().st_size


@requires_capstone
def test_top_mnemonics_is_list_of_dicts(thumb2_firmware):
    tops = disasm_stats.analyze(thumb2_firmware)["top_mnemonics"]
    assert isinstance(tops, list)
    for entry in tops:
        assert "mnemonic" in entry and "count" in entry
        assert isinstance(entry["mnemonic"], str)
        assert isinstance(entry["count"], int) and entry["count"] > 0


@requires_capstone
def test_top_mnemonics_sorted_descending(thumb2_firmware):
    tops = disasm_stats.analyze(thumb2_firmware)["top_mnemonics"]
    counts = [e["count"] for e in tops]
    assert counts == sorted(counts, reverse=True)


@requires_capstone
def test_top_mnemonics_capped_at_25(tmp_path):
    """Firmware with 30+ distinct mnemonics must return at most 25 top entries."""
    result = disasm_stats.analyze(tmp_path / "nonexistent_but_zero.bin" if False else
                                   _make_varied_firmware(tmp_path))
    assert len(result["top_mnemonics"]) <= 25


def _make_varied_firmware(tmp_path: Path) -> Path:
    # Reuse the zero firmware via a fresh path — low variety, but enough for cap test
    p = tmp_path / "varied.bin"
    p.write_bytes(bytes(range(256)) * 16)  # 4 KB of all byte values
    return p


@requires_capstone
def test_suspicious_is_dict(thumb2_firmware):
    susp = disasm_stats.analyze(thumb2_firmware)["suspicious"]
    assert isinstance(susp, dict)
    for key in ("bkpt", "svc", "udf"):
        assert key in susp
        assert isinstance(susp[key], int)


# ── Counting correctness ──────────────────────────────────────────────────────

@requires_capstone
def test_total_instructions_nonzero(thumb2_firmware):
    assert disasm_stats.analyze(thumb2_firmware)["total_instructions"] > 0


@requires_capstone
def test_function_prologues_correct(thumb2_firmware):
    # The fixture encodes exactly 4 PUSH {…, lr} instructions.
    result = disasm_stats.analyze(thumb2_firmware)
    assert result["function_prologues"] == 4, (
        f"expected 4 prologues, got {result['function_prologues']}; "
        f"top_mnemonics={result['top_mnemonics']}"
    )


@requires_capstone
def test_branch_instructions_nonzero(thumb2_firmware):
    # 4 BX LR instructions → at least 4 branches
    result = disasm_stats.analyze(thumb2_firmware)
    assert result["branch_instructions"] >= 4


@requires_capstone
def test_memory_instructions_nonzero(thumb2_firmware):
    # 4 PUSH + 3 LDR = 7 memory instructions
    result = disasm_stats.analyze(thumb2_firmware)
    assert result["memory_instructions"] >= 7


# ── load_address / arch_info ──────────────────────────────────────────────────

@requires_capstone
def test_default_load_address(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware)
    # Default is 0x08000000
    assert result["load_address"] == hex(0x0800_0000)


@requires_capstone
def test_arch_info_hex_string_parsed(thumb2_firmware):
    arch_info = {"inferred_load_address": "0x20000000"}
    result = disasm_stats.analyze(thumb2_firmware, arch_info=arch_info)
    assert result["load_address"] == "0x20000000"


@requires_capstone
def test_arch_info_none_uses_default(thumb2_firmware):
    result = disasm_stats.analyze(thumb2_firmware, arch_info=None)
    assert result["load_address"] == hex(0x0800_0000)


@requires_capstone
def test_arch_info_bad_value_falls_back(thumb2_firmware):
    # Garbage load address string must not crash — falls back to default
    result = disasm_stats.analyze(thumb2_firmware, arch_info={"inferred_load_address": "not_a_hex"})
    assert result["available"] is True
    assert result["load_address"] == hex(0x0800_0000)


# ── skipdata / edge cases ─────────────────────────────────────────────────────

@requires_capstone
def test_zero_firmware_does_not_crash(zero_firmware):
    result = disasm_stats.analyze(zero_firmware)
    assert isinstance(result, dict)
    assert result.get("available") is True


@requires_capstone
def test_zero_firmware_no_error(zero_firmware):
    assert disasm_stats.analyze(zero_firmware)["error"] is None


@requires_capstone
def test_no_prologue_in_zeros(zero_firmware):
    # 0x00 0x00 in Thumb is MOVS r0, r0 — valid but has no LR in op_str
    assert disasm_stats.analyze(zero_firmware)["function_prologues"] == 0


def test_missing_file_returns_available_false(tmp_path):
    """Non-existent path must return available=False, never raise."""
    result = disasm_stats.analyze(tmp_path / "does_not_exist.bin")
    assert result.get("available") is False
    assert result.get("error") is not None


def test_no_capstone_returns_available_false(monkeypatch, tmp_path):
    """Simulate missing capstone import."""
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "capstone":
            raise ImportError("no module named capstone")
        return real_import(name, *args, **kwargs)

    p = tmp_path / "dummy.bin"
    p.write_bytes(b"\x00" * 32)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    result = disasm_stats.analyze(p)
    assert result.get("available") is False
    assert "capstone" in (result.get("error") or "").lower()


# ── mnemonic normalisation (unit-level) ───────────────────────────────────────

def test_norm_strips_width_suffix():
    assert disasm_stats._norm("ldr.w") == "ldr"
    assert disasm_stats._norm("str.n") == "str"
    assert disasm_stats._norm("push.w") == "push"


def test_norm_collapses_conditional_branch():
    assert disasm_stats._norm("beq")  == "b"
    assert disasm_stats._norm("bne")  == "b"
    assert disasm_stats._norm("bgt")  == "b"
    assert disasm_stats._norm("bleq") == "bl"


def test_norm_leaves_unconditional_branch():
    assert disasm_stats._norm("b")   == "b"
    assert disasm_stats._norm("bl")  == "bl"
    assert disasm_stats._norm("bx")  == "bx"
    assert disasm_stats._norm("blx") == "blx"


def test_norm_leaves_non_branch():
    assert disasm_stats._norm("ldr")  == "ldr"
    assert disasm_stats._norm("push") == "push"
    assert disasm_stats._norm("it")   == "it"
