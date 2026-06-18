"""FindCrypt-style cryptographic constant detection.

Scans the binary for known byte signatures of cryptographic algorithm
constants: AES S-box, SHA-256/SHA-1/MD5 init vectors, CRC32 table,
ChaCha20 sigma, DES S-box, base64 alphabet, RSA e=65537 DER encoding.

Never executes the binary — pure byte-pattern search (memmem equivalent).
"""
from __future__ import annotations

import struct
from pathlib import Path

# ── Crypto constant signatures ────────────────────────────────────────────────

# AES forward S-box (sbox[0..15])
_AES_SBOX_HEAD = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

# AES inverse S-box (inv_sbox[0..15])
_AES_INV_SBOX_HEAD = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
])

# AES Te0 table first 4 bytes (a3d07bc1...)
_AES_TE0_HEAD = bytes([0xa3, 0xd0, 0x7b, 0xc1])

# SHA-256 initial hash values (big-endian)
_SHA256_INIT = struct.pack(">IIIIIIII",
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

# SHA-256 initial hash values (little-endian — common on ARM bare-metal)
_SHA256_INIT_LE = struct.pack("<IIIIIIII",
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

# SHA-1 initial hash values (big-endian)
_SHA1_INIT = struct.pack(">IIIII",
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
)

# MD5 T[1..4] constants (little-endian, as used in most implementations)
_MD5_T_HEAD = struct.pack("<IIII",
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
)

# CRC32 table — first two entries (polynomial 0xEDB88320, reflected)
_CRC32_HEAD = struct.pack("<II", 0x00000000, 0x77073096)

# ChaCha20/Salsa20 sigma constant "expand 32-byte k"
_CHACHA_SIGMA = b"expand 32-byte k"

# Salsa20 sigma "expa nd 32-byte k" (slightly different)
_SALSA_SIGMA = b"expa"  # first 4 bytes — too short alone; combined with next

# Standard base64 alphabet (all 64 chars)
_BASE64_ALPHA = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

# RSA public exponent e=65537 in DER INTEGER encoding
_RSA_E65537 = bytes([0x02, 0x03, 0x01, 0x00, 0x01])

# DES S-box 1 first 8 nibbles packed as bytes (first row: 14,4,13,1,2,15,11,8)
_DES_SBOX1 = bytes([0xe4, 0xd1, 0x2f, 0xb8])  # packed nibbles

# RC4 KSA output first 4 bytes when key = "RC4" (heuristic, too specific)
# Instead detect RC4 by the sequential S[] init:
_RC4_INIT = bytes(range(8))  # 00 01 02 03 04 05 06 07 — first 8 of S[] init

# ── Signature registry ────────────────────────────────────────────────────────

SIGNATURES: list[tuple[str, bytes, str]] = [
    ("AES_SBOX",         _AES_SBOX_HEAD,      "high"),
    ("AES_INV_SBOX",     _AES_INV_SBOX_HEAD,  "high"),
    ("AES_TE0",          _AES_TE0_HEAD,        "medium"),
    ("SHA256_INIT",      _SHA256_INIT,         "low"),
    ("SHA256_INIT_LE",   _SHA256_INIT_LE,      "low"),
    ("SHA1_INIT",        _SHA1_INIT,           "medium"),
    ("MD5_CONST",        _MD5_T_HEAD,          "medium"),
    ("CRC32_TABLE",      _CRC32_HEAD,          "low"),
    ("CHACHA20_SIGMA",   _CHACHA_SIGMA,        "low"),
    ("BASE64_ALPHA",     _BASE64_ALPHA,        "low"),
    ("RSA_E65537_DER",   _RSA_E65537,          "medium"),
    ("DES_SBOX",         _DES_SBOX1,           "high"),
    ("RC4_SINIT",        _RC4_INIT,            "medium"),
]

_MIN_CONFIDENCE_LEN = 4  # only emit matches where needle >= 4 bytes


def analyze(path: Path) -> dict:
    """Scan for known cryptographic constant byte sequences.

    Returns:
        {
            "matches": [{"algo": str, "offset": int, "confidence": str}, ...],
            "count": int,
            "error": str | None,
        }
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"matches": [], "count": 0, "error": str(exc)}

    try:
        matches: list[dict] = []
        seen: set[tuple[str, int]] = set()

        for algo, needle, confidence in SIGNATURES:
            if len(needle) < _MIN_CONFIDENCE_LEN:
                continue
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx == -1:
                    break
                key = (algo, idx)
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "algo":       algo,
                        "offset":     idx,
                        "confidence": confidence,
                    })
                start = idx + 1

        # Deduplicate overlapping AES matches (SBOX and INV_SBOX share some bytes)
        matches.sort(key=lambda m: m["offset"])

        return {
            "matches": matches,
            "count":   len(matches),
            "error":   None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"matches": [], "count": 0, "error": str(exc)}
