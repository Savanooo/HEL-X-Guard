"""Tests for Feature 4: entropy region map (classify_blocks + SVG heatmap data)."""
from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from firmware_scanner.entropy import (
    analyze,
    classify_blocks,
    _classify,
    _CLASS_ENCRYPTED,
    _CLASS_COMPRESSED,
    _CLASS_CODE,
    _CLASS_DATA,
    _CLASS_TEXT,
    _CLASS_PADDING,
    _CLASS_COLORS,
    BLOCK_SIZE,
)


# ── _classify() ───────────────────────────────────────────────────────────────

def test_classify_encrypted():
    assert _classify(7.9) == _CLASS_ENCRYPTED


def test_classify_compressed():
    assert _classify(7.0) == _CLASS_COMPRESSED
    assert _classify(6.0) == _CLASS_COMPRESSED


def test_classify_code():
    assert _classify(5.5) == _CLASS_CODE
    assert _classify(4.0) == _CLASS_CODE


def test_classify_data():
    assert _classify(3.0) == _CLASS_DATA
    assert _classify(2.0) == _CLASS_DATA


def test_classify_text():
    assert _classify(1.5) == _CLASS_TEXT
    assert _classify(0.5) == _CLASS_TEXT


def test_classify_padding():
    assert _classify(0.0) == _CLASS_PADDING
    assert _classify(0.4) == _CLASS_PADDING


def test_classify_exact_boundaries():
    assert _classify(7.5) == _CLASS_COMPRESSED   # 7.5 is not > 7.5
    assert _classify(6.0) == _CLASS_COMPRESSED
    assert _classify(4.0) == _CLASS_CODE
    assert _classify(2.0) == _CLASS_DATA
    assert _classify(0.5) == _CLASS_TEXT


# ── classify_blocks() ─────────────────────────────────────────────────────────

def test_classify_blocks_empty():
    assert classify_blocks([]) == []


def test_classify_blocks_single_block():
    blk = [{"offset": 0, "size": 1024, "entropy": 7.8}]
    regions = classify_blocks(blk)
    assert len(regions) == 1
    assert regions[0]["class"] == _CLASS_ENCRYPTED
    assert regions[0]["offset"] == 0
    assert regions[0]["size"] == 1024


def test_classify_blocks_merges_same_class():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 7.8},
        {"offset": 1024, "size": 1024, "entropy": 7.6},
    ]
    regions = classify_blocks(blks)
    assert len(regions) == 1
    assert regions[0]["class"] == _CLASS_ENCRYPTED
    assert regions[0]["size"] == 2048


def test_classify_blocks_separates_different_classes():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 7.8},   # encrypted
        {"offset": 1024, "size": 1024, "entropy": 3.0},   # data
    ]
    regions = classify_blocks(blks)
    assert len(regions) == 2
    assert regions[0]["class"] == _CLASS_ENCRYPTED
    assert regions[1]["class"] == _CLASS_DATA


def test_classify_blocks_required_keys():
    blks = [{"offset": 0, "size": 512, "entropy": 5.0}]
    regions = classify_blocks(blks)
    for r in regions:
        assert "offset"  in r
        assert "size"    in r
        assert "entropy" in r
        assert "class"   in r
        assert "color"   in r


def test_classify_blocks_color_is_valid_hex():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 7.8},
        {"offset": 1024, "size": 1024, "entropy": 3.0},
    ]
    regions = classify_blocks(blks)
    for r in regions:
        color = r["color"]
        assert color.startswith("#")
        assert len(color) == 7   # #rrggbb


def test_classify_blocks_preserves_total_size():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 7.8},
        {"offset": 1024, "size": 512,  "entropy": 1.0},
        {"offset": 1536, "size": 512,  "entropy": 3.0},
    ]
    regions = classify_blocks(blks)
    total = sum(r["size"] for r in regions)
    assert total == 2048


def test_classify_blocks_weighted_average_entropy():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 8.0},
        {"offset": 1024, "size": 1024, "entropy": 7.6},
    ]
    regions = classify_blocks(blks)
    # Both "encrypted" → merged; average = 7.8
    assert regions[0]["entropy"] == pytest.approx(7.8, abs=0.001)


def test_classify_blocks_three_alternating_classes():
    blks = [
        {"offset": 0,    "size": 1024, "entropy": 7.8},  # encrypted
        {"offset": 1024, "size": 1024, "entropy": 0.1},  # padding
        {"offset": 2048, "size": 1024, "entropy": 7.9},  # encrypted
    ]
    regions = classify_blocks(blks)
    assert len(regions) == 3
    assert regions[0]["class"] == _CLASS_ENCRYPTED
    assert regions[1]["class"] == _CLASS_PADDING
    assert regions[2]["class"] == _CLASS_ENCRYPTED


# ── analyze() integration ─────────────────────────────────────────────────────

def test_analyze_includes_regions_key(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 2048)
    r = analyze(p)
    assert "regions" in r


def test_analyze_regions_is_list(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00" * 2048)
    r = analyze(p)
    assert isinstance(r["regions"], list)


def test_analyze_zero_file_regions_is_padding(tmp_path):
    p = tmp_path / "zeros.bin"
    p.write_bytes(b"\x00" * BLOCK_SIZE * 4)
    r = analyze(p)
    assert len(r["regions"]) == 1
    assert r["regions"][0]["class"] == _CLASS_PADDING


def test_analyze_high_entropy_block_produces_encrypted_region(tmp_path):
    """A file with 2 KB of ~random bytes should produce an 'encrypted' region."""
    rng = random.Random(0xBEEF)
    # Construct a near-uniform byte distribution over 2048 bytes
    # (repeat bytes(range(256)) × 8 = 2048 bytes — perfectly uniform, entropy=8.0)
    hi_ent = bytes(range(256)) * 8
    data = hi_ent
    p = tmp_path / "hi.bin"
    p.write_bytes(data)
    r = analyze(p, block_size=BLOCK_SIZE)
    encrypted_regions = [reg for reg in r["regions"] if reg["class"] == _CLASS_ENCRYPTED]
    assert len(encrypted_regions) >= 1


def test_analyze_mixed_file_multiple_regions(tmp_path):
    """File with clear high-entropy and zero sections → at least 2 regions."""
    hi_ent = bytes(range(256)) * 4   # 1024 bytes, entropy = 8.0
    padding = b"\x00" * 1024
    p = tmp_path / "mixed.bin"
    p.write_bytes(hi_ent + padding)
    r = analyze(p, block_size=BLOCK_SIZE)
    assert len(r["regions"]) >= 2


def test_analyze_regions_cover_full_file(tmp_path):
    hi_ent = bytes(range(256)) * 4   # 1024 bytes
    padding = b"\x00" * 1024
    p = tmp_path / "full.bin"
    p.write_bytes(hi_ent + padding)
    r = analyze(p, block_size=BLOCK_SIZE)
    total = sum(reg["size"] for reg in r["regions"])
    assert total == 2048


def test_analyze_regions_first_offset_is_zero(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"\xaa" * 4096)
    r = analyze(p)
    assert r["regions"][0]["offset"] == 0


def test_analyze_backward_compat_blocks_still_present(tmp_path):
    """analyze() must still return 'blocks' (backward compatibility)."""
    p = tmp_path / "b.bin"
    p.write_bytes(b"\x00" * 2048)
    r = analyze(p)
    assert "blocks" in r
    assert isinstance(r["blocks"], list)


# ── Color map completeness ─────────────────────────────────────────────────────

def test_all_classes_have_colors():
    for cls in (_CLASS_ENCRYPTED, _CLASS_COMPRESSED, _CLASS_CODE,
                _CLASS_DATA, _CLASS_TEXT, _CLASS_PADDING):
        assert cls in _CLASS_COLORS
        assert _CLASS_COLORS[cls].startswith("#")
