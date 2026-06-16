from __future__ import annotations

from pathlib import Path

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
    # Detect API version: yara-python 4.3+ uses StringMatch objects
    _NEW_API = hasattr(yara, "StringMatch")
except ImportError:
    _YARA_AVAILABLE = False
    _NEW_API = False

DEFAULT_RULES_PATH = Path(__file__).parent.parent.parent / "rules" / "firmware_rules.yar"


def _serialize_match(match: object) -> dict:
    """Convert a yara.Match object to a JSON-serializable dict."""
    severity = "low"
    if hasattr(match, "meta") and isinstance(match.meta, dict):
        severity = match.meta.get("severity", "low")

    strings_matched: list[dict] = []

    if _NEW_API:
        # yara-python 4.3+: match.strings is a list of StringMatch objects
        for sm in getattr(match, "strings", []):
            for instance in getattr(sm, "instances", []):
                strings_matched.append({
                    "identifier": getattr(sm, "identifier", ""),
                    "offset": getattr(instance, "offset", 0),
                    "data": repr(getattr(instance, "matched_data", b"")),
                })
    else:
        # yara-python < 4.3: match.strings is a list of (offset, identifier, data) tuples
        for item in getattr(match, "strings", []):
            if isinstance(item, tuple) and len(item) == 3:
                strings_matched.append({
                    "identifier": item[1],
                    "offset": item[0],
                    "data": repr(item[2]),
                })

    return {
        "rule": getattr(match, "rule", ""),
        "namespace": getattr(match, "namespace", "default"),
        "tags": list(getattr(match, "tags", [])),
        "severity": severity,
        "strings": strings_matched,
    }


def scan(path: Path, rules_path: Path = DEFAULT_RULES_PATH) -> dict:
    """Scan a file against compiled YARA rules.

    Never raises — errors are captured in the "error" field.

    Returns:
        {"matches": list[dict], "error": str | None}
    """
    if not _YARA_AVAILABLE:
        return {
            "matches": [],
            "error": "yara-python is not installed; YARA scanning skipped",
        }

    if not rules_path.exists():
        return {
            "matches": [],
            "error": f"YARA rules file not found: {rules_path}",
        }

    try:
        rules = yara.compile(filepath=str(rules_path))
    except Exception as e:
        return {"matches": [], "error": f"Failed to compile YARA rules: {e}"}

    try:
        matches = rules.match(str(path))
    except Exception as e:
        return {"matches": [], "error": f"YARA scan error: {e}"}

    return {
        "matches": [_serialize_match(m) for m in matches],
        "error": None,
    }
