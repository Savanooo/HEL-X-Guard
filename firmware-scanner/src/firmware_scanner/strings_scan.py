from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

MIN_LENGTH = 6
CHUNK_SIZE = 64 * 1024

_ASCII_RE   = re.compile(rb'[\x20-\x7e]{6,}')
_UTF16LE_RE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')

_PATTERNS: dict[str, re.Pattern] = {
    "PRIVATE_KEY": re.compile(
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    ),
    "CERTIFICATE": re.compile(r'-----BEGIN CERTIFICATE-----'),
    "API_KEY": re.compile(
        r'(?:'
        r'AKIA[0-9A-Z]{16}'                                          # AWS access key
        r'|ASIA[0-9A-Z]{16}'                                         # AWS temporary key
        r'|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'  # JWT
        r'|[0-9a-fA-F]{40,}'                                         # hex key/hash (SHA1+)
        r'|[A-Za-z0-9+/]{60,}={1,2}'                                 # base64 with padding
        r')'
    ),
    "CREDENTIAL": re.compile(
        r'(?:password|passwd|secret|key|token|pwd)\s*[=:]\s*\S+',
        re.IGNORECASE,
    ),
    "URL": re.compile(r'https?://[^\s"\'<>]{8,}', re.IGNORECASE),
    "IP": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "DOMAIN": re.compile(
        r'\b(?:[a-z0-9\-]+\.){1,}(?:com|net|org|io|ru|cn|tk|xyz|gov|edu)\b',
        re.IGNORECASE,
    ),
    "SHELL_COMMAND": re.compile(
        r'(?:chmod|bash|/bin/sh|sh\s+-c|wget|curl)\s+\S+',
        re.IGNORECASE,
    ),
    "DEBUG_KEYWORD": re.compile(
        r'\b(?:backdoor|debug_mode|test_mode|hardcoded|factory_reset'
        r'|ENABLE_DEBUG|service_mode|engineering_mode|maintenance_mode'
        r'|diagnostic_mode|TODO|FIXME|HACK|XXX)\b',
        re.IGNORECASE,
    ),
    "NETWORK_SERVICE": re.compile(
        r'\b(?:telnet|ftp|tftp|ssh|admin)\b.*\b\d{1,5}\b',
        re.IGNORECASE,
    ),
    "VERSION": re.compile(
        r'(?:[Vv]ersion|[Ff][Ww]\s*[Vv]er|SW\s*[Vv]er|HW\s*[Vv]er)\s*[:\s]\s*\d+\.\d+[\.\d]*',
    ),
    "CRYPTO": re.compile(
        r'\b(?:MD5|SHA-?1\b|3DES|RC4|DES\b|ECB|AES-?128|AES-?256|RSA-?\d{3,4})\b',
        re.IGNORECASE,
    ),
}

_CATEGORY_PRIORITY = [
    "PRIVATE_KEY",
    "CERTIFICATE",
    "API_KEY",
    "CREDENTIAL",
    "URL",
    "IP",
    "DOMAIN",
    "SHELL_COMMAND",
    "DEBUG_KEYWORD",
    "NETWORK_SERVICE",
    "CRYPTO",
    "VERSION",
]


def _is_repetitive(s: str, max_period: int = 4, threshold: float = 0.85) -> bool:
    """Detect ARM/machine-code byte patterns that appear as repetitive ASCII strings.

    Two-stage filter:
    1. Low character diversity (≤4 unique chars in a long string) → machine code.
    2. Short repeating unit, allowing a few irregular chars at the start.

    Real API keys, JWTs, hex hashes are pseudo-random and have diverse chars.
    Machine code byte sequences (e.g. 'MkMkMk', 'BBJBJB', 'cMkMkMk') do not.
    """
    n = len(s)
    if n < 16:
        return False
    # Stage 1: very few unique characters → almost certainly machine-code artifact
    if len(set(s)) <= 5:
        return True
    # Stage 2: repeating unit check, with small skip to handle non-repeating prefix
    max_skip = min(6, n // 4)
    for skip in range(max_skip + 1):
        body = s[skip:]
        nb = len(body)
        for period in range(1, min(max_period + 1, nb // 2 + 1)):
            matches = sum(body[i] == body[i % period] for i in range(nb))
            if matches / nb >= threshold:
                return True
    return False


def _classify(s: str) -> str | None:
    if _is_repetitive(s):
        return None
    for category in _CATEGORY_PRIORITY:
        if _PATTERNS[category].search(s):
            return category
    return None


def _is_mostly_printable(s: str) -> bool:
    if not s:
        return False
    non_alnum = sum(1 for c in s if not (c.isalnum() or c.isspace()))
    return (non_alnum / len(s)) <= 0.30


def _decode(raw: bytes, encoding: str) -> str | None:
    try:
        if encoding == "ascii":
            return raw.decode("ascii")
        s = raw.decode("utf-16-le").rstrip("\x00")
        return s if _is_mostly_printable(s) else None
    except UnicodeDecodeError:
        return None


def _iter_raw_strings(
    path: Path,
    pattern: re.Pattern,
    encoding: str,
    min_length: int,
    chunk_size: int,
) -> Iterator[tuple[str, int, str]]:
    """Stream-extract strings matching pattern with correct chunk-boundary handling.

    A printable run that extends to the very end of the read buffer may continue
    in the next chunk.  We defer it until it is terminated by a non-printable byte
    or by EOF, so strings crossing chunk boundaries are emitted in their full form.
    """
    partial_bytes = b""
    partial_offset = 0
    file_offset = 0

    with open(path, "rb") as f:
        while True:
            raw = f.read(chunk_size)
            is_last = len(raw) < chunk_size

            buffer = partial_bytes + raw
            buf_start = file_offset - len(partial_bytes)  # absolute offset of buffer[0]

            matches = list(pattern.finditer(buffer))
            partial_bytes = b""

            for i, m in enumerate(matches):
                is_final  = (i == len(matches) - 1)
                spans_end = (m.end() == len(buffer))

                if is_final and spans_end and not is_last:
                    # Run may continue — defer to next iteration
                    partial_bytes  = m.group()
                    partial_offset = buf_start + m.start()
                else:
                    s = _decode(m.group(), encoding)
                    if s is not None and len(s) >= min_length:
                        yield s, buf_start + m.start(), encoding

            file_offset += len(raw)
            if is_last:
                break

    # Flush any remaining deferred partial (terminated by EOF)
    if partial_bytes:
        s = _decode(partial_bytes, encoding)
        if s is not None and len(s) >= min_length:
            yield s, partial_offset, encoding


def scan(
    path: Path,
    min_length: int = MIN_LENGTH,
    chunk_size: int = CHUNK_SIZE,
) -> dict:
    """Extract and classify strings from a binary file.

    Returns:
        {
            "total": int,
            "suspicious": [{"value": str, "category": str, "offset": int, "encoding": str}, ...],
            "suspicious_count": int
        }
    """
    total = 0
    suspicious: list[dict] = []
    seen_offsets: set[int] = set()

    for encoding, pattern in [("ascii", _ASCII_RE), ("utf16le", _UTF16LE_RE)]:
        for value, offset, enc in _iter_raw_strings(path, pattern, encoding, min_length, chunk_size):
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)
            total += 1

            category = _classify(value)
            if category:
                suspicious.append({
                    "value": value,
                    "category": category,
                    "offset": offset,
                    "encoding": enc,
                })

    return {
        "total": total,
        "suspicious": suspicious,
        "suspicious_count": len(suspicious),
    }
