"""CVE cross-reference against offline curated dataset (rules/cve_db.json).

Matches detected components (from components.py) against a local offline
CVE database. No external API calls — deterministic, air-gap-friendly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / "rules" / "cve_db.json"


def _version_affected(detected: str, affected_versions: list[str]) -> bool:
    """Return True if detected version matches any entry in affected_versions.

    Matching rules (simple, no semver library required):
    - Exact string match.
    - Prefix match when an entry ends with '*' (e.g. "10.4.*").
    - Range check when an entry is "<=X.Y.Z" or "<X.Y.Z".
    """
    d = detected.strip()
    for entry in affected_versions:
        entry = entry.strip()
        if entry.endswith("*"):
            if d.startswith(entry[:-1]):
                return True
        elif entry.startswith("<="):
            try:
                if _ver_tuple(d) <= _ver_tuple(entry[2:]):
                    return True
            except Exception:
                if d == entry[2:]:
                    return True
        elif entry.startswith("<"):
            try:
                if _ver_tuple(d) < _ver_tuple(entry[1:]):
                    return True
            except Exception:
                pass
        elif d == entry:
            return True
    return False


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Convert "1.2.3" → (1, 2, 3). Non-numeric trailing parts stripped."""
    parts = []
    for seg in v.split("."):
        seg = "".join(c for c in seg if c.isdigit())
        parts.append(int(seg) if seg else 0)
    return tuple(parts)


def match(
    components_result: dict,
    db_path: Path = _DEFAULT_DB,
) -> dict:
    """Cross-reference detected components against the offline CVE database.

    Returns:
        {
            "matches": [
                {
                    "component": str,
                    "version": str,
                    "cve_id": str,
                    "cvss": float,
                    "severity": str,
                    "summary": str,
                },
                ...
            ],
            "count": int,
            "error": str | None,
        }
    """
    try:
        if not db_path.exists():
            return {
                "matches": [],
                "count":   0,
                "error":   f"CVE database not found: {db_path}",
            }

        db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))
        detected = components_result.get("components", [])

        cve_matches: list[dict] = []
        for comp in detected:
            name    = comp.get("component", "")
            version = comp.get("version", "")
            if not name or not version:
                continue

            for entry in db:
                if entry.get("component", "").lower() != name.lower():
                    continue
                if _version_affected(version, entry.get("affected_versions", [])):
                    cve_matches.append({
                        "component": name,
                        "version":   version,
                        "cve_id":    entry.get("cve_id", ""),
                        "cvss":      entry.get("cvss"),
                        "severity":  entry.get("severity", "unknown"),
                        "summary":   entry.get("summary", ""),
                    })

        return {
            "matches": cve_matches,
            "count":   len(cve_matches),
            "error":   None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"matches": [], "count": 0, "error": str(exc)}
