"""Tests for crypto_constants.py — FindCrypt-style byte pattern scanner."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from firmware_scanner import crypto_constants


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def aes_sbox_file(tmp_path_factory) -> Path:
    """File containing the AES S-box signature at a known offset."""
    tmp = tmp_path_factory.mktemp("crypto")
    p   = tmp / "aes.bin"
    prefix = b"\x00" * 32
    sbox_head = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])
    p.write_bytes(prefix + sbox_head + b"\x00" * 256)
    return p


@pytest.fixture(scope="session")
def chacha_file(tmp_path_factory) -> Path:
    """File with ChaCha20 sigma constant."""
    tmp = tmp_path_factory.mktemp("chacha")
    p   = tmp / "chacha.bin"
    p.write_bytes(b"\x00" * 64 + b"expand 32-byte k" + b"\x00" * 32)
    return p


@pytest.fixture(scope="session")
def sha256_file(tmp_path_factory) -> Path:
    """File with SHA-256 initial hash values (big-endian)."""
    tmp  = tmp_path_factory.mktemp("sha256")
    p    = tmp / "sha256.bin"
    init = struct.pack(">IIIIIIII",
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    )
    p.write_bytes(b"\x00" * 16 + init + b"\x00" * 32)
    return p


@pytest.fixture(scope="session")
def empty_file(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("empty")
    p   = tmp / "empty.bin"
    p.write_bytes(b"")
    return p


# ── Return structure ──────────────────────────────────────────────────────────

def test_returns_dict(synthetic_firmware_file):
    result = crypto_constants.analyze(synthetic_firmware_file)
    assert isinstance(result, dict)


def test_required_keys(synthetic_firmware_file):
    result = crypto_constants.analyze(synthetic_firmware_file)
    assert "matches" in result
    assert "count"   in result
    assert "error"   in result


def test_matches_is_list(synthetic_firmware_file):
    result = crypto_constants.analyze(synthetic_firmware_file)
    assert isinstance(result["matches"], list)


def test_count_matches_list_length(synthetic_firmware_file):
    result = crypto_constants.analyze(synthetic_firmware_file)
    assert result["count"] == len(result["matches"])


def test_match_entry_structure(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    if result["matches"]:
        m = result["matches"][0]
        assert "algo"       in m
        assert "offset"     in m
        assert "confidence" in m
        assert isinstance(m["offset"], int)
        assert m["confidence"] in ("low", "medium", "high")


# ── Positive detections ────────────────────────────────────────────────────────

def test_detects_aes_sbox(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    algos  = {m["algo"] for m in result["matches"]}
    assert "AES_SBOX" in algos


def test_aes_sbox_offset_correct(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    aes_m  = [m for m in result["matches"] if m["algo"] == "AES_SBOX"]
    assert aes_m, "AES_SBOX not detected"
    assert aes_m[0]["offset"] == 32  # prefix length


def test_detects_chacha20(chacha_file):
    result = crypto_constants.analyze(chacha_file)
    algos  = {m["algo"] for m in result["matches"]}
    assert "CHACHA20_SIGMA" in algos


def test_detects_sha256_init(sha256_file):
    result = crypto_constants.analyze(sha256_file)
    algos  = {m["algo"] for m in result["matches"]}
    assert "SHA256_INIT" in algos or "SHA256_INIT_LE" in algos


def test_confidence_high_for_aes(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    aes_m  = [m for m in result["matches"] if m["algo"] == "AES_SBOX"]
    assert aes_m[0]["confidence"] == "high"


# ── Negative / edge cases ─────────────────────────────────────────────────────

def test_empty_file_no_matches(empty_file):
    result = crypto_constants.analyze(empty_file)
    assert result["matches"] == []
    assert result["count"]   == 0
    assert result["error"]   is None


def test_zero_file_no_matches(all_zero_file):
    result = crypto_constants.analyze(all_zero_file)
    assert result["count"] == 0


def test_no_error_on_valid_input(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    assert result["error"] is None


def test_matches_are_sorted_by_offset(aes_sbox_file):
    result = crypto_constants.analyze(aes_sbox_file)
    offsets = [m["offset"] for m in result["matches"]]
    assert offsets == sorted(offsets)
