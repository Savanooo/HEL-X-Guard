"""SBOM — embedded software component and library version detection.

Scans for version banner strings emitted by common embedded libraries
at build time (e.g. "FreeRTOS V10.4.3", "libcurl/7.81.0").
Output is the input for cve_match.py CVE cross-reference.

Never executes the binary — pure byte-scan with compiled regexes.
"""
from __future__ import annotations

import re
from pathlib import Path

# Each entry: (component_name, compiled_bytes_regex)
# The regex must capture the version in group 1.
_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("FreeRTOS",  re.compile(rb'FreeRTOS\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("lwIP",      re.compile(rb'lwIP\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("mbedTLS",   re.compile(rb'mbed\s*TLS\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("wolfSSL",   re.compile(rb'wolfSSL\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("OpenSSL",   re.compile(rb'OpenSSL\s+(\d+\.\d+[\.\d]*[a-z]?)', re.I)),
    ("zlib",      re.compile(rb'zlib\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("BusyBox",   re.compile(rb'BusyBox\s+[Vv]?(\d+\.\d+[\.\d]*)')),
    ("mongoose",  re.compile(rb'Mongoose/(\d+\.\d+[\.\d]*)')),
    ("libcurl",   re.compile(rb'libcurl/(\d+\.\d+[\.\d]*)', re.I)),
    ("expat",     re.compile(rb'expat/(\d+\.\d+[\.\d]*)', re.I)),
    ("newlib",    re.compile(rb'(?:newlib|Newlib)\s+[Vv]?(\d+\.\d+[\.\d]*)')),
    ("GCC",       re.compile(rb'GCC:\s*\([^)]*\)\s*(\d+\.\d+[\.\d]*)')),
    ("uClibc",    re.compile(rb'uClibc[- ][Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("musl",      re.compile(rb'musl libc\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("Dropbear",  re.compile(rb'Dropbear\s+[Vv]?(\d+\.\d+[\.\d]*)', re.I)),
    ("miniupnp",  re.compile(rb'miniupnp(?:d|c)[/ ][Vv]?(\d+\.\d+[\.\d]*)', re.I)),
]

_MAX_EVIDENCE_LEN = 80


def analyze(path: Path) -> dict:
    """Detect embedded library version banners in firmware.

    Returns:
        {
            "components": [
                {
                    "component": str,
                    "version": str,
                    "evidence_offset": int,
                    "evidence": str,
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
        return {"components": [], "count": 0, "error": str(exc)}

    try:
        components: list[dict] = []
        seen: set[str] = set()

        for name, pattern in _PATTERNS:
            for m in pattern.finditer(data):
                if name in seen:
                    break  # one detection per component is enough
                try:
                    version = m.group(1).decode("ascii", errors="replace").strip()
                except Exception:
                    continue

                evidence_raw = m.group(0)[:_MAX_EVIDENCE_LEN]
                evidence = evidence_raw.decode("ascii", errors="replace").rstrip("\x00")

                components.append({
                    "component":      name,
                    "version":        version,
                    "evidence_offset": m.start(),
                    "evidence":       evidence,
                })
                seen.add(name)

        return {
            "components": components,
            "count":      len(components),
            "error":      None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"components": [], "count": 0, "error": str(exc)}
