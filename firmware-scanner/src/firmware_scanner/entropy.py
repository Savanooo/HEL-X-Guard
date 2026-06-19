from __future__ import annotations

import math
import collections
from pathlib import Path

BLOCK_SIZE = 1024       # 1 KB per entropy block
CHUNK_SIZE = 64 * 1024  # 64 KB file read chunk

THRESHOLD_HIGH = 7.5
THRESHOLD_MED  = 6.0

# ── Region classification thresholds ─────────────────────────────────────────
# Block entropy → region class label
_CLASS_ENCRYPTED   = "encrypted"    # > 7.5 — extremely high, likely crypto/compressed
_CLASS_COMPRESSED  = "compressed"   # 6.0–7.5 — high but not necessarily encrypted
_CLASS_CODE        = "code"         # 4.0–6.0 — typical executable code
_CLASS_DATA        = "data"         # 2.0–4.0 — structured data / tables
_CLASS_TEXT        = "text"         # 0.5–2.0 — ASCII / UTF-8 strings
_CLASS_PADDING     = "padding"      # < 0.5 — zero-fill or repeated bytes

_CLASS_COLORS: dict[str, str] = {
    _CLASS_ENCRYPTED:  "#ef4444",   # red
    _CLASS_COMPRESSED: "#f97316",   # orange
    _CLASS_CODE:       "#3b82f6",   # blue
    _CLASS_DATA:       "#8b5cf6",   # purple
    _CLASS_TEXT:       "#22c55e",   # green
    _CLASS_PADDING:    "#374151",   # grey
}


def _classify(entropy: float) -> str:
    if entropy > 7.5:
        return _CLASS_ENCRYPTED
    if entropy >= 6.0:
        return _CLASS_COMPRESSED
    if entropy >= 4.0:
        return _CLASS_CODE
    if entropy >= 2.0:
        return _CLASS_DATA
    if entropy >= 0.5:
        return _CLASS_TEXT
    return _CLASS_PADDING


def classify_blocks(blocks: list[dict]) -> list[dict]:
    """Merge adjacent same-class blocks into contiguous regions.

    Args:
        blocks: List of block dicts from ``analyze()``, each containing
                ``offset``, ``size``, and ``entropy`` keys.

    Returns:
        List of region dicts::

            [
                {
                    "offset":  int,    # byte offset of region start
                    "size":    int,    # total bytes in region
                    "entropy": float,  # average entropy across constituent blocks
                    "class":   str,    # one of: encrypted, compressed, code,
                                       #         data, text, padding
                    "color":   str,    # CSS hex color for visualization
                },
                ...
            ]
    """
    if not blocks:
        return []

    regions: list[dict] = []
    cur_class  = _classify(blocks[0]["entropy"])
    cur_offset = blocks[0]["offset"]
    cur_size   = blocks[0]["size"]
    cur_ent_sum = blocks[0]["entropy"] * blocks[0]["size"]
    cur_bytes   = blocks[0]["size"]

    for blk in blocks[1:]:
        blk_class = _classify(blk["entropy"])
        if blk_class == cur_class:
            cur_size    += blk["size"]
            cur_ent_sum += blk["entropy"] * blk["size"]
            cur_bytes   += blk["size"]
        else:
            avg_ent = cur_ent_sum / cur_bytes if cur_bytes else 0.0
            regions.append({
                "offset":  cur_offset,
                "size":    cur_size,
                "entropy": round(avg_ent, 4),
                "class":   cur_class,
                "color":   _CLASS_COLORS[cur_class],
            })
            cur_class   = blk_class
            cur_offset  = blk["offset"]
            cur_size    = blk["size"]
            cur_ent_sum = blk["entropy"] * blk["size"]
            cur_bytes   = blk["size"]

    avg_ent = cur_ent_sum / cur_bytes if cur_bytes else 0.0
    regions.append({
        "offset":  cur_offset,
        "size":    cur_size,
        "entropy": round(avg_ent, 4),
        "class":   cur_class,
        "color":   _CLASS_COLORS[cur_class],
    })

    return regions


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
        "regions": classify_blocks(blocks),
        "interpretation": _interpret(overall),
    }
