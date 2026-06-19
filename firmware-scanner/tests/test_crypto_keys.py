"""Tests for Feature 3: crypto key / key-material extraction."""
from __future__ import annotations

import math
import random
from pathlib import Path

import pytest

from firmware_scanner import crypto_keys, risk_scoring
from firmware_scanner.crypto_keys import (
    _extract_iv_candidates,
    _extract_pem,
    _extract_weak_keys,
    _extract_high_entropy_blobs,
    _shannon,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def all_zero_key_blob(tmp_path) -> Path:
    """32-byte all-zero key embedded in a realistic binary."""
    data = b"\x00" * 512 + b"\x41" * 128 + b"\x00" * 32 + b"\x42" * 128
    p = tmp_path / "zero_key.bin"
    p.write_bytes(data)
    return p


@pytest.fixture
def sequential_key_blob(tmp_path) -> Path:
    """16-byte sequential key (0x00–0x0f)."""
    padding = b"\xcc" * 64
    key = bytes(range(16))
    data = padding + key + padding
    p = tmp_path / "seq_key.bin"
    p.write_bytes(data)
    return p


@pytest.fixture
def high_entropy_blob_file(tmp_path) -> Path:
    """File with a 32-byte high-entropy blob (all 32 bytes distinct) surrounded by zero padding.

    bytes(range(0, 256, 8)) gives [0, 8, 16, …, 248] — 32 distinct bytes.
    Empirical entropy = log2(32) ≈ 5.0 bits/byte, comfortably above the
    size-adjusted threshold of 0.88 * log2(32) ≈ 4.4 bits/byte.
    """
    blob = bytes(range(0, 256, 8))   # 32 distinct byte values
    data = b"\x00" * 256 + blob + b"\x00" * 256
    p = tmp_path / "hi_ent.bin"
    p.write_bytes(data)
    return p


@pytest.fixture
def pem_private_key_blob(tmp_path) -> Path:
    p = tmp_path / "pem.bin"
    pem = (
        b"some firmware header\x00\x00\x00"
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA3a9cGMxrjMEY9xB0u+PbBqTj2d9VXXXXXXXXXXXXXXXX==\n"
        b"-----END RSA PRIVATE KEY-----\n"
        b"\x00" * 128
    )
    p.write_bytes(pem)
    return p


@pytest.fixture
def pem_certificate_blob(tmp_path) -> Path:
    p = tmp_path / "cert.bin"
    data = (
        b"\x00" * 64
        + b"-----BEGIN CERTIFICATE-----\n"
        + b"MIICpDCCAYwCCQD4gFOFRHb+yTANBgkqhkiG9w0BAQUFADAXXXXXXXXXXXXX==\n"
        + b"-----END CERTIFICATE-----\n"
        + b"\x00" * 64
    )
    p.write_bytes(data)
    return p


@pytest.fixture
def iv_adjacent_blob(tmp_path) -> Path:
    """16-byte medium-entropy blob immediately after 'AES' string."""
    rng = random.Random(42)
    iv = bytes(rng.randint(0, 255) for _ in range(16))
    data = b"\x00" * 128 + b"AES\x00" + iv + b"\x00" * 128
    p = tmp_path / "iv.bin"
    p.write_bytes(data)
    return p


# ── Shannon entropy helper ────────────────────────────────────────────────────

def test_shannon_all_same():
    assert _shannon(b"\x00" * 64) == 0.0


def test_shannon_uniform():
    data = bytes(range(256))
    assert abs(_shannon(data) - 8.0) < 0.001


def test_shannon_empty():
    assert _shannon(b"") == 0.0


# ── Structure ─────────────────────────────────────────────────────────────────

def test_analyze_returns_dict(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"\x00" * 64)
    r = crypto_keys.analyze(p)
    assert isinstance(r, dict)


def test_analyze_required_keys(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"\x00" * 64)
    r = crypto_keys.analyze(p)
    for k in ("available", "keys", "count", "has_private", "error"):
        assert k in r


def test_analyze_never_raises(tmp_path):
    r = crypto_keys.analyze(tmp_path / "nonexistent.bin")
    assert isinstance(r, dict)
    assert r.get("available") is False


def test_analyze_empty_binary(tmp_path):
    p = tmp_path / "e.bin"
    p.write_bytes(b"\x00" * 256)
    r = crypto_keys.analyze(p)
    assert r["available"] is True
    # All-zero 16/24/32-byte regions ARE weak keys → may have findings
    # but no private keys
    assert r["has_private"] is False


# ── Weak key detection ────────────────────────────────────────────────────────

def test_all_zero_key_detected(all_zero_key_blob):
    r = crypto_keys.analyze(all_zero_key_blob)
    weak = [k for k in r["keys"] if k["type"] == "weak_key"]
    assert len(weak) > 0


def test_sequential_key_detected(sequential_key_blob):
    r = crypto_keys.analyze(sequential_key_blob)
    weak = [k for k in r["keys"] if k["type"] == "weak_key"]
    assert any(k["size"] == 16 for k in weak)


def test_weak_key_has_required_fields(all_zero_key_blob):
    r = crypto_keys.analyze(all_zero_key_blob)
    for k in r["keys"]:
        assert "offset" in k
        assert "size"   in k
        assert "type"   in k
        assert "label"  in k
        assert "context" in k


def test_repeated_byte_key_detected(tmp_path):
    """0xAA × 16 repeated pattern should be flagged."""
    p = tmp_path / "aa_key.bin"
    p.write_bytes(b"\x11" * 64 + b"\xaa" * 16 + b"\x11" * 64)
    r = crypto_keys.analyze(p)
    weak = [k for k in r["keys"] if k["type"] == "weak_key"]
    assert len(weak) > 0


def test_extract_weak_keys_direct():
    data = b"\xde\xad" * 64 + b"\x00" * 16 + b"\xde\xad" * 64
    results = _extract_weak_keys(data)
    assert any(r["size"] == 16 for r in results)


# ── High-entropy blob detection ───────────────────────────────────────────────

def test_high_entropy_blob_detected(high_entropy_blob_file):
    r = crypto_keys.analyze(high_entropy_blob_file)
    hi = [k for k in r["keys"] if k["type"] == "high_entropy_blob"]
    assert len(hi) > 0


def test_high_entropy_blob_has_entropy_field(high_entropy_blob_file):
    r = crypto_keys.analyze(high_entropy_blob_file)
    hi = [k for k in r["keys"] if k["type"] == "high_entropy_blob"]
    for h in hi:
        assert h["entropy"] is not None
        assert h["entropy"] >= 4.0   # size-adjusted threshold for 32-byte blob


def test_extract_high_entropy_blobs_direct():
    # 32 distinct bytes → entropy = log2(32) ≈ 5.0, above 0.88*5.0=4.4 threshold
    blob = bytes(range(0, 256, 8))
    data = b"\x00" * 512 + blob + b"\x00" * 512
    results = _extract_high_entropy_blobs(data)
    assert any(r["entropy"] >= 4.0 for r in results)


def test_all_zero_binary_no_high_entropy(tmp_path):
    p = tmp_path / "z.bin"
    p.write_bytes(b"\x00" * 1024)
    r = crypto_keys.analyze(p)
    hi = [k for k in r["keys"] if k["type"] == "high_entropy_blob"]
    assert len(hi) == 0


# ── PEM extraction ────────────────────────────────────────────────────────────

def test_pem_private_key_detected(pem_private_key_blob):
    r = crypto_keys.analyze(pem_private_key_blob)
    pem_keys = [k for k in r["keys"] if k["type"] == "pem_private_key"]
    assert len(pem_keys) >= 1
    assert r["has_private"] is True


def test_pem_certificate_detected(pem_certificate_blob):
    r = crypto_keys.analyze(pem_certificate_blob)
    certs = [k for k in r["keys"] if k["type"] == "pem_certificate"]
    assert len(certs) >= 1


def test_extract_pem_direct():
    data = (
        b"header\x00"
        b"-----BEGIN EC PRIVATE KEY-----\n"
        b"XXXXXXXXXXXXXXXX==\n"
        b"-----END EC PRIVATE KEY-----\n"
    )
    results = _extract_pem(data)
    assert any(r["type"] == "pem_private_key" for r in results)


def test_pem_entropy_is_none(pem_private_key_blob):
    r = crypto_keys.analyze(pem_private_key_blob)
    pem_keys = [k for k in r["keys"] if k["type"] == "pem_private_key"]
    for k in pem_keys:
        assert k["entropy"] is None


# ── IV candidate detection ────────────────────────────────────────────────────

def test_iv_candidate_detected(iv_adjacent_blob):
    r = crypto_keys.analyze(iv_adjacent_blob)
    ivs = [k for k in r["keys"] if k["type"] == "iv_candidate"]
    assert len(ivs) >= 1


def test_extract_iv_candidates_direct():
    rng = random.Random(9)
    iv = bytes(rng.randint(0, 255) for _ in range(16))
    data = b"\x00" * 64 + b"AES\x00" + iv + b"\x00" * 64
    results = _extract_iv_candidates(data)
    assert len(results) >= 1
    assert results[0]["type"] == "iv_candidate"


# ── Risk scoring integration ──────────────────────────────────────────────────

def test_risk_score_no_crypto_keys_result():
    r = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )
    assert isinstance(r["score"], int)


def test_risk_score_with_private_key():
    ck = {
        "available": True,
        "keys": [{"type": "pem_private_key", "size": 1800, "entropy": None,
                  "offset": 0, "label": "PEM private key", "context": "2d2d2d"}],
        "count": 1,
        "has_private": True,
    }
    base = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )["score"]
    with_ck = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )["score"]
    assert with_ck == base + 30  # W_CK_PRIVATE_KEY


def test_risk_score_with_weak_key():
    ck = {
        "available": True,
        "keys": [{"type": "weak_key", "size": 32, "entropy": 0.0,
                  "offset": 0, "label": "All-zero key", "context": "00" * 16}],
        "count": 1,
        "has_private": False,
    }
    base = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )["score"]
    with_ck = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )["score"]
    assert with_ck == base + 20  # W_CK_WEAK_KEY


def test_risk_score_with_high_entropy_32_blob():
    ck = {
        "available": True,
        "keys": [{"type": "high_entropy_blob", "size": 32, "entropy": 7.9,
                  "offset": 0, "label": "HE blob", "context": "aabbcc"}],
        "count": 1,
        "has_private": False,
    }
    base = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )["score"]
    with_ck = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )["score"]
    assert with_ck == base + 15  # W_CK_HIGH_ENT_BLOB (size == 32)


def test_risk_score_high_entropy_16_blob_not_counted():
    """16-byte high-entropy blob should NOT contribute (< 32 bytes)."""
    ck = {
        "available": True,
        "keys": [{"type": "high_entropy_blob", "size": 16, "entropy": 7.9,
                  "offset": 0, "label": "HE blob", "context": "aabbcc"}],
        "count": 1,
        "has_private": False,
    }
    base = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )["score"]
    with_ck = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )["score"]
    assert with_ck == base


def test_risk_reasons_mention_key_material():
    ck = {
        "available": True,
        "keys": [],
        "count": 0,
        "has_private": True,
    }
    r = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )
    assert any("private key" in reason.lower() or "crypto" in reason.lower()
               for reason in r["reasons"])


def test_weak_key_cap_applied():
    """3 weak keys × 20 = 60 → capped at CAP_CK_WEAK=40."""
    keys = [
        {"type": "weak_key", "size": 16, "entropy": 0.0,
         "offset": i * 100, "label": "weak", "context": "00" * 16}
        for i in range(3)
    ]
    ck = {"available": True, "keys": keys, "count": 3, "has_private": False}
    base = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
    )["score"]
    with_ck = risk_scoring.score(
        {"overall": 0.0, "blocks": []},
        {"suspicious": [], "category_counts": {}},
        {"matches": []},
        crypto_keys_result=ck,
    )["score"]
    assert with_ck == min(100, base + 40)  # capped at 40


# ── Count / sort ──────────────────────────────────────────────────────────────

def test_findings_sorted_by_offset(tmp_path):
    """Findings from analyze() should be ordered by ascending offset."""
    rng = random.Random(77)
    blob1 = bytes(rng.randint(0, 255) for _ in range(32))
    blob2 = bytes(rng.randint(0, 255) for _ in range(32))
    data = b"\x00" * 64 + blob1 + b"\x00" * 256 + blob2 + b"\x00" * 64
    p = tmp_path / "sorted.bin"
    p.write_bytes(data)
    r = crypto_keys.analyze(p)
    offsets = [k["offset"] for k in r["keys"]]
    assert offsets == sorted(offsets)


def test_count_matches_keys_length(tmp_path):
    p = tmp_path / "m.bin"
    p.write_bytes(b"\x00" * 64)
    r = crypto_keys.analyze(p)
    assert r["count"] == len(r["keys"])
