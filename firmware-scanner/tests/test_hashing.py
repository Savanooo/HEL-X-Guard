from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from firmware_scanner import hashing


def test_returns_expected_keys(synthetic_firmware_file):
    result = hashing.hash_file(synthetic_firmware_file)
    assert set(result.keys()) == {"md5", "sha1", "sha256"}


def test_hash_values_match_precomputed(synthetic_firmware_file, known_hashes):
    result = hashing.hash_file(synthetic_firmware_file)
    assert result["md5"]    == known_hashes["md5"]
    assert result["sha1"]   == known_hashes["sha1"]
    assert result["sha256"] == known_hashes["sha256"]


def test_different_files_have_different_sha256(synthetic_firmware_file, all_zero_file):
    r1 = hashing.hash_file(synthetic_firmware_file)
    r2 = hashing.hash_file(all_zero_file)
    assert r1["sha256"] != r2["sha256"]


def test_streaming_matches_full_read(synthetic_firmware_file):
    """Chunked streaming must produce same digest as hashlib on raw bytes."""
    data = synthetic_firmware_file.read_bytes()
    expected_sha256 = hashlib.sha256(data).hexdigest()
    result = hashing.hash_file(synthetic_firmware_file, chunk_size=64)
    assert result["sha256"] == expected_sha256


def test_invalid_path_raises():
    with pytest.raises(FileNotFoundError):
        hashing.hash_file(Path("/nonexistent/path/firmware.bin"))


def test_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    result = hashing.hash_file(empty)
    assert result["md5"]    == "d41d8cd98f00b204e9800998ecf8427e"
    assert result["sha1"]   == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert result["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_values_are_lowercase_hex(synthetic_firmware_file):
    result = hashing.hash_file(synthetic_firmware_file)
    for key in ("md5", "sha1", "sha256"):
        assert result[key] == result[key].lower()
        assert all(c in "0123456789abcdef" for c in result[key])
