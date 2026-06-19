"""Crypto key / key-material extraction (Feature 3).

Heuristics applied (static, read-only — firmware bytes are never executed):

1.  **PEM/DER markers** — search for standard BEGIN … END headers and decode
    the inner base64; extract offset, size, type, and whether it's a private key.

2.  **High-entropy isolated blobs** — scan 16/24/32-byte windows; flag any
    window with Shannon entropy ≥ 7.2 that is not immediately preceded or
    followed by similar high-entropy material (i.e. not part of a compressed
    block).  These are candidates for raw AES keys, HMAC secrets, or session
    tokens.

3.  **Weak / test keys** — detect all-zero, all-0xFF, sequential (0x00 01 02 …),
    repeated single-byte patterns, and known public test vectors (e.g. NIST
    AES-128 test key ``000102030405060708090a0b0c0d0e0f``).

4.  **IV-like constants adjacent to crypto code** — 16-byte blocks that follow
    immediately after a known crypto algorithm identifier string (AES, DES,
    RC4, ChaCha20) within 64 bytes; labelled ``iv_candidate``.

Each finding is a dict::

    {
        "offset":   int,          # byte offset in the binary
        "size":     int,          # blob size in bytes
        "type":     str,          # "pem_private_key", "pem_public_key",
                                  # "pem_certificate", "high_entropy_blob",
                                  # "weak_key", "iv_candidate"
        "entropy":  float,        # Shannon entropy (0.0–8.0), None for PEM
        "label":    str,          # human-readable label
        "context":  str,          # short hex preview (first 16 bytes)
    }

Risk contributions (consumed by risk_scoring.score):
  - Any private key       → +30 (same as W_PRIVATE_KEY)
  - High-entropy blob ≥32B → +15 per (capped at 30 total)
  - Weak key              → +20 each (capped at 40 total)
"""
from __future__ import annotations

import math
import re
from pathlib import Path


# ── PEM marker patterns ───────────────────────────────────────────────────────

_PEM_PATTERNS: list[tuple[str, str]] = [
    ("pem_private_key",   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("pem_public_key",    r"-----BEGIN (?:RSA |EC |DSA )?PUBLIC KEY-----"),
    ("pem_certificate",   r"-----BEGIN CERTIFICATE-----"),
    ("pem_certificate",   r"-----BEGIN X509 CERTIFICATE-----"),
    ("pem_crl",           r"-----BEGIN X509 CRL-----"),
    ("pem_csr",           r"-----BEGIN CERTIFICATE REQUEST-----"),
    ("pem_pkcs12",        r"-----BEGIN PKCS12-----"),
    ("pem_pgp",           r"-----BEGIN PGP (?:PRIVATE KEY BLOCK|PUBLIC KEY BLOCK|MESSAGE)-----"),
]

_PEM_END = re.compile(rb"-----END [A-Z0-9 ]+-----")

# ── Weak key patterns ─────────────────────────────────────────────────────────

_KNOWN_TEST_KEYS: frozenset[bytes] = frozenset({
    # NIST AES-128 test key
    bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
    # NIST AES-256 test key
    bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    # All-zero 16
    b"\x00" * 16,
    # All-zero 24
    b"\x00" * 24,
    # All-zero 32
    b"\x00" * 32,
    # All-0xFF 16 / 24 / 32
    b"\xff" * 16,
    b"\xff" * 24,
    b"\xff" * 32,
    # Sequential (also called "incremental") 16-byte
    bytes(range(16)),
    bytes(range(16, 32)),
    bytes(range(32, 48)),
    # Repeated single-byte patterns (0xAA, 0x55 — common test patterns)
    b"\xaa" * 16,
    b"\xaa" * 32,
    b"\x55" * 16,
    b"\x55" * 32,
    b"\xde\xad\xbe\xef" * 4,
    b"\xca\xfe\xba\xbe" * 4,
})

# ── Crypto algorithm identifiers (for IV-candidate heuristic) ─────────────────

_CRYPTO_STRINGS = [
    b"AES",
    b"DES",
    b"3DES",
    b"RC4",
    b"ChaCha",
    b"Blowfish",
    b"Twofish",
]

# ── Key sizes we consider meaningful ─────────────────────────────────────────

_KEY_SIZES = (16, 24, 32)   # AES-128, AES-192, AES-256 in bytes

# ── Entropy thresholds for "isolated high-entropy blob" ──────────────────────
# For whole-file analysis 7.2 bits/byte is the standard threshold.
# For small windows (16/24/32 bytes) the theoretical maximum entropy is
# log2(window_size) ≈ 4.0–5.0 bits/byte (achievable only when every byte
# in the window is distinct).  We require ≥ 88 % of that theoretical maximum.

def _entropy_threshold(size: int) -> float:
    """Return the minimum entropy (bits/byte) required to flag a blob of *size* bytes."""
    return max(3.5, math.log2(size) * 0.88)

# Minimum entropy of the *surrounding* context blocks to consider a blob
# "isolated" (not part of a larger compressed region)
_CONTEXT_ENTROPY_MAX = 5.5


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shannon(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def _hex_preview(blob: bytes, n: int = 16) -> str:
    return blob[:n].hex()


def _is_isolated(data: bytes, offset: int, size: int) -> bool:
    """Return True if the blob is not surrounded by other high-entropy data."""
    ctx_size = max(size, 64)
    before_start = max(0, offset - ctx_size)
    before = data[before_start:offset]
    after_end = min(len(data), offset + size + ctx_size)
    after = data[offset + size:after_end]
    before_ent = _shannon(before) if before else 0.0
    after_ent  = _shannon(after)  if after  else 0.0
    return before_ent < _CONTEXT_ENTROPY_MAX or after_ent < _CONTEXT_ENTROPY_MAX


def _is_repeated_byte(blob: bytes) -> bool:
    return len(set(blob)) == 1


def _is_sequential(blob: bytes) -> bool:
    """Return True if blob is an ascending or descending byte sequence."""
    if len(blob) < 4:
        return False
    diffs = [blob[i + 1] - blob[i] for i in range(len(blob) - 1)]
    return all(d == diffs[0] for d in diffs)


# ── Extraction functions ──────────────────────────────────────────────────────

def _extract_pem(data: bytes) -> list[dict]:
    findings: list[dict] = []
    for key_type, pattern_str in _PEM_PATTERNS:
        pattern = re.compile(pattern_str.encode())
        for m in pattern.finditer(data):
            start = m.start()
            # find matching END marker within 8 KB
            end_m = _PEM_END.search(data, start, start + 8192)
            if not end_m:
                continue
            end = end_m.end()
            blob = data[start:end]
            findings.append({
                "offset":  start,
                "size":    end - start,
                "type":    key_type,
                "entropy": None,
                "label":   f"PEM block: {key_type.replace('pem_', '').replace('_', ' ')}",
                "context": _hex_preview(blob),
            })
    return findings


def _extract_high_entropy_blobs(data: bytes) -> list[dict]:
    """Slide a 16/24/32-byte window and flag isolated high-entropy blobs."""
    findings: list[dict] = []
    seen: set[int] = set()   # track offsets where a finding was already recorded

    n = len(data)
    for size in _KEY_SIZES:
        threshold = _entropy_threshold(size)
        step = max(1, size // 4)
        for offset in range(0, n - size + 1, step):
            if offset in seen:
                continue
            blob = data[offset:offset + size]
            ent = _shannon(blob)
            if ent < threshold:
                continue
            if not _is_isolated(data, offset, size):
                continue
            seen.add(offset)
            findings.append({
                "offset":  offset,
                "size":    size,
                "type":    "high_entropy_blob",
                "entropy": round(ent, 3),
                "label":   f"High-entropy {size * 8}-bit blob (entropy {ent:.2f})",
                "context": _hex_preview(blob),
            })
    return findings


def _extract_weak_keys(data: bytes) -> list[dict]:
    findings: list[dict] = []
    n = len(data)

    for size in _KEY_SIZES:
        for offset in range(0, n - size + 1, 1):
            blob = data[offset:offset + size]

            if blob in _KNOWN_TEST_KEYS:
                label = "Known test/NIST key"
            elif _is_repeated_byte(blob):
                b = blob[0]
                label = f"Repeated-byte key (0x{b:02x})"
            elif _is_sequential(blob):
                label = "Sequential-byte key"
            else:
                continue

            findings.append({
                "offset":  offset,
                "size":    size,
                "type":    "weak_key",
                "entropy": round(_shannon(blob), 3),
                "label":   label,
                "context": _hex_preview(blob),
            })

    # Deduplicate: if multiple sizes match at same offset, keep the largest
    seen_offsets: dict[int, dict] = {}
    for f in findings:
        o = f["offset"]
        if o not in seen_offsets or f["size"] > seen_offsets[o]["size"]:
            seen_offsets[o] = f
    return list(seen_offsets.values())


def _extract_iv_candidates(data: bytes) -> list[dict]:
    """Find 16-byte blocks immediately following known crypto algorithm strings."""
    findings: list[dict] = []
    n = len(data)

    for cs in _CRYPTO_STRINGS:
        for m in re.finditer(re.escape(cs), data):
            # Look for a 16-byte block within 64 bytes of the identifier
            for delta in range(0, 64):
                iv_start = m.end() + delta
                iv_end = iv_start + 16
                if iv_end > n:
                    break
                blob = data[iv_start:iv_end]
                ent = _shannon(blob)
                # IV candidates: not all-zero, entropy between 3 and 8
                if ent < 3.0:
                    continue
                findings.append({
                    "offset":  iv_start,
                    "size":    16,
                    "type":    "iv_candidate",
                    "entropy": round(ent, 3),
                    "label":   f"IV candidate near '{cs.decode()}' identifier",
                    "context": _hex_preview(blob),
                })
                break   # take first plausible 16-byte block per identifier

    # Remove duplicates by offset
    seen: set[int] = set()
    unique = []
    for f in findings:
        if f["offset"] not in seen:
            seen.add(f["offset"])
            unique.append(f)
    return unique


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(path: Path, _arch_info: dict | None = None) -> dict:
    """Extract crypto key material from a firmware binary.

    Args:
        path: Path to the binary file to analyse.

    Returns::

        {
            "available":   True,
            "keys":        [<finding>, ...],
            "count":       int,
            "has_private": bool,       # True if any PEM private key found
            "error":       str | None,
        }

    Never raises.
    """
    try:
        return _do_analyze(path)
    except Exception as exc:  # noqa: BLE001
        return {
            "available":   False,
            "keys":        [],
            "count":       0,
            "has_private": False,
            "error":       str(exc),
        }


def _do_analyze(path: Path) -> dict:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {
            "available":   False,
            "keys":        [],
            "count":       0,
            "has_private": False,
            "error":       str(exc),
        }

    findings: list[dict] = []
    findings += _extract_pem(data)
    findings += _extract_weak_keys(data)
    findings += _extract_high_entropy_blobs(data)
    findings += _extract_iv_candidates(data)

    # Remove cross-type duplicates: if an offset is already covered by PEM or
    # weak_key, drop the high_entropy_blob at the same offset.
    priority_offsets: set[int] = {
        f["offset"] for f in findings if f["type"] in ("pem_private_key", "pem_public_key", "pem_certificate", "weak_key")
    }
    findings = [
        f for f in findings
        if f["type"] not in ("high_entropy_blob", "iv_candidate") or f["offset"] not in priority_offsets
    ]

    # Sort by offset
    findings.sort(key=lambda f: f["offset"])

    has_private = any(f["type"] == "pem_private_key" for f in findings)

    return {
        "available":   True,
        "keys":        findings,
        "count":       len(findings),
        "has_private": has_private,
        "error":       None,
    }
