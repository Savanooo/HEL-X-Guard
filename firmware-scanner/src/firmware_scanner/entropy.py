from __future__ import annotations

import math
import collections
from pathlib import Path

BLOCK_SIZE = 1024       # 1 KB per entropy block
CHUNK_SIZE = 64 * 1024  # 64 KB file read chunk

THRESHOLD_HIGH = 7.5
THRESHOLD_MED  = 6.0


def _shannon_entropy(counter: collections.Counter, total: int) -> float:
    """Compute Shannon entropy (bits per byte, 0.0–8.0) from a byte frequency counter."""
    if total == 0:
        return 0.0
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counter.values()
        if count > 0
    )


def _interpret(entropy: float) -> str:
    if entropy > THRESHOLD_HIGH:
        return "likely encrypted or compressed"
    if entropy >= THRESHOLD_MED:
        return "mixed content (partially compressed or binary)"
    return "plain or low-entropy data"


def analyze(path: Path, block_size: int = BLOCK_SIZE) -> dict:
    """Stream a file and compute overall + per-block Shannon entropy.

    Handles chunk/block boundary misalignment without loading the whole file.

    Returns:
        {
            "overall": float,
            "blocks": [{"block": int, "offset": int, "size": int, "entropy": float}, ...],
            "interpretation": str
        }
    """
    overall_counter: collections.Counter = collections.Counter()
    overall_total = 0

    blocks = []
    block_buf = bytearray()
    block_index = 0
    block_start_offset = 0
    file_offset = 0

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            overall_counter.update(chunk)
            overall_total += len(chunk)

            pos = 0
            while pos < len(chunk):
                space = block_size - len(block_buf)
                piece = chunk[pos : pos + space]
                block_buf.extend(piece)
                pos += len(piece)

                if len(block_buf) == block_size:
                    c = collections.Counter(block_buf)
                    blocks.append({
                        "block": block_index,
                        "offset": block_start_offset,
                        "size": block_size,
                        "entropy": round(_shannon_entropy(c, block_size), 4),
                    })
                    block_index += 1
                    block_start_offset += block_size
                    block_buf = bytearray()

            file_offset += len(chunk)

    # Flush any remaining partial block
    if block_buf:
        c = collections.Counter(block_buf)
        blocks.append({
            "block": block_index,
            "offset": block_start_offset,
            "size": len(block_buf),
            "entropy": round(_shannon_entropy(c, len(block_buf)), 4),
        })

    overall = round(_shannon_entropy(overall_counter, overall_total), 4)

    return {
        "overall": overall,
        "blocks": blocks,
        "interpretation": _interpret(overall),
    }
