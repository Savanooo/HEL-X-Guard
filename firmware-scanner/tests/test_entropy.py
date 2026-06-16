from __future__ import annotations

import pytest

from firmware_scanner import entropy


def test_zero_file_overall_entropy(all_zero_file):
    result = entropy.analyze(all_zero_file)
    assert result["overall"] == 0.0


def test_zero_file_interpretation(all_zero_file):
    result = entropy.analyze(all_zero_file)
    assert result["interpretation"] == "plain or low-entropy data"


def test_uniform_file_near_max_entropy(uniform_file):
    result = entropy.analyze(uniform_file)
    # 256 uniform values → entropy close to 8.0
    assert result["overall"] >= 7.9


def test_overall_entropy_in_range(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file)
    assert 0.0 <= result["overall"] <= 8.0


def test_blocks_cover_all_bytes(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file, block_size=512)
    file_size = synthetic_firmware_file.stat().st_size
    total_covered = sum(b["size"] for b in result["blocks"])
    assert total_covered == file_size


def test_block_offsets_are_monotonic(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file, block_size=256)
    offsets = [b["offset"] for b in result["blocks"]]
    assert offsets == sorted(offsets)


def test_blocks_are_non_overlapping(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file, block_size=512)
    blocks = result["blocks"]
    for i in range(len(blocks) - 1):
        assert blocks[i]["offset"] + blocks[i]["size"] == blocks[i + 1]["offset"]


def test_high_entropy_interpretation():
    assert entropy._interpret(7.6) == "likely encrypted or compressed"


def test_medium_entropy_interpretation():
    assert entropy._interpret(7.0) == "mixed content (partially compressed or binary)"
    assert entropy._interpret(6.0) == "mixed content (partially compressed or binary)"


def test_low_entropy_interpretation():
    assert entropy._interpret(5.9) == "plain or low-entropy data"
    assert entropy._interpret(0.0) == "plain or low-entropy data"


def test_custom_block_size(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file, block_size=2048)
    file_size = synthetic_firmware_file.stat().st_size
    expected_blocks = -(-file_size // 2048)  # ceiling division
    assert len(result["blocks"]) == expected_blocks


def test_last_block_partial(synthetic_firmware_file):
    file_size = synthetic_firmware_file.stat().st_size
    block_size = 1000  # intentionally not a power of 2
    result = entropy.analyze(synthetic_firmware_file, block_size=block_size)
    last_block = result["blocks"][-1]
    if file_size % block_size != 0:
        assert last_block["size"] == file_size % block_size
    else:
        assert last_block["size"] == block_size


def test_result_has_required_keys(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file)
    assert "overall" in result
    assert "blocks" in result
    assert "interpretation" in result


def test_each_block_has_required_keys(synthetic_firmware_file):
    result = entropy.analyze(synthetic_firmware_file, block_size=512)
    for block in result["blocks"]:
        assert "block" in block
        assert "offset" in block
        assert "size" in block
        assert "entropy" in block
        assert 0.0 <= block["entropy"] <= 8.0
