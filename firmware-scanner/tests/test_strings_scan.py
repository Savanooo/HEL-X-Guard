from __future__ import annotations

from pathlib import Path

import pytest

from firmware_scanner import strings_scan


def _suspicious_by_category(result: dict, category: str) -> list[dict]:
    return [s for s in result["suspicious"] if s["category"] == category]


def test_finds_url(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    urls = _suspicious_by_category(result, "URL")
    values = [s["value"] for s in urls]
    assert any("malicious-c2.example.com" in v for v in values)


def test_finds_credential(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    creds = _suspicious_by_category(result, "CREDENTIAL")
    values = [s["value"] for s in creds]
    assert any("password" in v.lower() or "secret" in v.lower() for v in values)


def test_finds_private_key_header(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    keys = _suspicious_by_category(result, "PRIVATE_KEY")
    assert len(keys) >= 1
    assert any("BEGIN RSA PRIVATE KEY" in s["value"] for s in keys)


def test_finds_aws_api_key(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    api_keys = _suspicious_by_category(result, "API_KEY")
    values = [s["value"] for s in api_keys]
    assert any("AKIA" in v for v in values)


def test_finds_debug_keyword(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    debug = _suspicious_by_category(result, "DEBUG_KEYWORD")
    values = [s["value"] for s in debug]
    assert any("backdoor" in v.lower() for v in values)


def test_finds_shell_command(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    shells = _suspicious_by_category(result, "SHELL_COMMAND")
    assert len(shells) >= 1


def test_finds_ip_address(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    ips = _suspicious_by_category(result, "IP")
    values = [s["value"] for s in ips]
    assert any("192.168.1.100" in v for v in values)


def test_total_gte_suspicious(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    assert result["total"] >= result["suspicious_count"]
    assert result["suspicious_count"] == len(result["suspicious"])


def test_each_entry_has_required_fields(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    for entry in result["suspicious"]:
        assert "value" in entry
        assert "category" in entry
        assert "offset" in entry
        assert "encoding" in entry
        assert entry["encoding"] in ("ascii", "utf16le")


def test_min_length_respected(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file, min_length=8)
    for entry in result["suspicious"]:
        assert len(entry["value"]) >= 8


def test_no_duplicates_by_offset(synthetic_firmware_file):
    result = strings_scan.scan(synthetic_firmware_file)
    offsets = [s["offset"] for s in result["suspicious"]]
    assert len(offsets) == len(set(offsets)), "Duplicate offsets found in suspicious list"


def test_chunk_boundary_no_duplicates(tmp_path):
    """A string spanning a 64-byte chunk boundary must appear exactly once.

    Uses '!' padding: printable ASCII (0x21) but NOT a hex digit or base64 char,
    so it cannot trigger API_KEY patterns that would shadow CREDENTIAL.
    """
    marker = b"password=hunter2secret"
    chunk = 64
    # '!' = 0x21, printable, not in [0-9a-fA-F] or [A-Za-z0-9+/]
    data = b"!" * (chunk - 5) + marker + b"!" * 100
    fw = tmp_path / "boundary.bin"
    fw.write_bytes(data)

    result = strings_scan.scan(fw, chunk_size=chunk)
    creds = _suspicious_by_category(result, "CREDENTIAL")
    assert len(creds) == 1, f"Expected 1 credential match, got {len(creds)}"


def test_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    result = strings_scan.scan(empty)
    assert result["total"] == 0
    assert result["suspicious_count"] == 0
    assert result["suspicious"] == []


def test_utf16_detection(tmp_path):
    """UTF-16 LE encoded string should be detected."""
    encoded = "password=secret".encode("utf-16-le")
    fw = tmp_path / "utf16.bin"
    fw.write_bytes(b"\x00" * 10 + encoded + b"\x00" * 10)
    result = strings_scan.scan(fw)
    utf16_matches = [s for s in result["suspicious"] if s["encoding"] == "utf16le"]
    assert len(utf16_matches) >= 1
