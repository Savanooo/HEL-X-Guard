"""X.509 certificate extractor (Tier 3 — optional).

Finds PEM and DER-encoded X.509 certificates embedded in firmware.
Parses each one to extract: subject, issuer, validity window, serial
number, and whether it is already expired.

Requires the `cryptography` package (pip install cryptography).
Never executes the binary.
"""
from __future__ import annotations

import base64
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
    re.DOTALL,
)

# DER SEQUENCE tag + 2-byte length: 0x30 0x82 <hi> <lo>
# We look for 0x30 0x82 and then parse the length to bound a candidate.
_DER_MAGIC = b"\x30\x82"

_MIN_DER_LEN = 64    # certificates are at least ~64 bytes
_MAX_DER_LEN = 8192  # skip implausibly large blobs


def analyze(path: Path) -> dict:
    """Extract and parse embedded X.509 certificates.

    Returns:
        {
            "certificates": [
                {
                    "type": "pem" | "der",
                    "offset": int,
                    "subject": str,
                    "issuer": str,
                    "not_before": str,    # ISO-8601
                    "not_after": str,     # ISO-8601
                    "is_expired": bool,
                    "serial": str,
                    "parse_error": bool,  # present only if parse failed
                },
                ...
            ],
            "count": int,
            "error": str | None,
        }
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"certificates": [], "count": 0, "error": str(exc)}

    # Check for cryptography library early
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.backends import default_backend  # type: ignore
        _crypto_available = True
    except ImportError:
        _crypto_available = False

    try:
        certs: list[dict] = []
        pem_offsets: set[int] = set()

        # ── PEM certificates ──────────────────────────────────────────────────
        for m in _PEM_RE.finditer(data):
            offset = m.start()
            pem_offsets.add(offset)
            try:
                der = base64.b64decode(
                    m.group(1).replace(b"\n", b"").replace(b"\r", b"")
                )
                if _crypto_available:
                    info = _parse_der(der, offset, "pem", x509, default_backend)
                else:
                    info = {"type": "pem", "offset": offset, "parse_error": True,
                            "error_detail": "cryptography library not installed"}
            except Exception as exc:
                info = {"type": "pem", "offset": offset, "parse_error": True,
                        "error_detail": str(exc)}
            certs.append(info)

        # ── DER certificates (heuristic) ──────────────────────────────────────
        if _crypto_available:
            pos = 0
            while True:
                idx = data.find(_DER_MAGIC, pos)
                if idx == -1:
                    break
                pos = idx + 1

                # Any PEM cert was already decoded above — skip its DER bytes
                if any(abs(idx - p) < 512 for p in pem_offsets):
                    continue

                if idx + 4 > len(data):
                    continue

                length = (data[idx + 2] << 8) | data[idx + 3]
                total  = length + 4  # tag (1) + len-of-len-byte (1) + 2-byte-len + payload

                if total < _MIN_DER_LEN or total > _MAX_DER_LEN:
                    continue
                if idx + total > len(data):
                    continue

                candidate = data[idx: idx + total]
                try:
                    info = _parse_der(candidate, idx, "der", x509, default_backend)
                    if "parse_error" not in info:
                        certs.append(info)
                except Exception:
                    pass

        return {"certificates": certs, "count": len(certs), "error": None}

    except Exception as exc:  # noqa: BLE001
        return {"certificates": [], "count": 0, "error": str(exc)}


def _parse_der(der: bytes, offset: int, cert_type: str, x509, default_backend) -> dict:
    cert = x509.load_der_x509_certificate(der, default_backend())

    # Compatibility with cryptography < 42 (not_valid_after_utc) and >= 42
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        na = cert.not_valid_after
        not_after = na.replace(tzinfo=timezone.utc)

    try:
        not_before = cert.not_valid_before_utc
    except AttributeError:
        nb = cert.not_valid_before
        not_before = nb.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    return {
        "type":       cert_type,
        "offset":     offset,
        "subject":    cert.subject.rfc4514_string(),
        "issuer":     cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after":  not_after.isoformat(),
        "is_expired": not_after < now,
        "serial":     str(cert.serial_number),
    }
