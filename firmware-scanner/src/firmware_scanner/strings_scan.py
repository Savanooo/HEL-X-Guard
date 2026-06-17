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
        r'AKIA[0-9A-Z]{16}'
        r'|ASIA[0-9A-Z]{16}'
        r'|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
        r'|[0-9a-fA-F]{32,}'
        r'|[A-Za-z0-9+/]{40,}={0,2}'
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
        r'\b(?:backdoor|debug_mode|test_mode|hardcoded|TODO|FIXME|factory_reset)\b',
        re.IGNORECASE,
    ),
    "NETWORK_SERVICE": re.compile(
        r'\b(?:telnet|ftp|tftp|ssh|admin)\b.*\b\d{1,5}\b',
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
]


def _is_repetitive(s: str, max_period: int = 4, threshold: float = 0.80) -> bool:
    """Detect ARM/machine-code byte patterns that appear as repetitive ASCII strings.

    e.g. 'MkMkMkMkMk', 'BBJBJBJB', 'snkmkmkm' — all have a short repeating unit.
    Real API keys/credentials are pseudo-random and won't pass this check.
    """
    n = len(s)
    if n < 12:
        return False
    for period in range(1, min(max_period + 1, n // 2 + 1)):
        matches = sum(s[i] == s[i % period] for i in range(n))
        if matches / n >= threshold:
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
