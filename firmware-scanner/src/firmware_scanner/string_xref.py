"""Post-decompile cross-reference: map suspicious strings to Ghidra functions.

Works purely in Python on the decompile_json produced by ghidra_runner.decompile().
No additional Ghidra invocations are made.  Called automatically by the decompile
runner step when Ghidra output is available.

Thumb-mode note: Ghidra function addresses in ARM firmware have the LSB set
(Thumb bit).  We mask it off with addr &= ~1 before storing so addresses are
consistent with the values used in the disasm endpoint.
"""
from __future__ import annotations


def analyze(
    decompile_result: dict,
    strings_result: dict,
    max_per_finding: int = 5,
) -> dict:
    """Map suspicious string values to the decompiled functions that contain them.

    Returns:
        {
          "available": bool,    # mirrors decompile_result["available"]
          "xrefs": [
            {
              "value":     str,   # the suspicious string value
              "category":  str,   # string category (CREDENTIAL, URL, etc.)
              "functions": [{"name": str, "address": str}, ...]
            },
            ...           # only entries with ≥ 1 matching function
          ],
          "error": None | str,
        }
    """
    try:
        return _do_analyze(decompile_result, strings_result, max_per_finding)
    except Exception as exc:
        return {"available": False, "xrefs": [], "error": str(exc)}


def _do_analyze(decompile_result: dict, strings_result: dict, max_per_finding: int) -> dict:
    if not decompile_result.get("available", True):
        return {
            "available": False,
            "xrefs": [],
            "error": "Ghidra decompilation not available",
        }

    functions: list[dict] = decompile_result.get("functions", [])
    if not functions:
        return {"available": True, "xrefs": [], "error": None}

    # Pre-process function list: clean addresses and keep code for fast search
    fn_entries: list[dict] = [
        {
            "name":    fn.get("name") or "unknown",
            "address": _clean_addr(fn.get("address", "")),
            "code":    fn.get("code") or "",
        }
        for fn in functions
    ]

    xrefs: list[dict] = []
    seen: set[str] = set()

    for item in strings_result.get("suspicious", []):
        value    = item.get("value") or ""
        category = item.get("category") or ""

        # Skip empty, very short, or already-processed values
        if len(value) < 4 or value in seen:
            continue
        seen.add(value)

        matched = _find_functions(fn_entries, value, max_per_finding)
        if matched:
            xrefs.append({"value": value, "category": category, "functions": matched})

    return {"available": True, "xrefs": xrefs, "error": None}


def _find_functions(fn_entries: list[dict], value: str, limit: int) -> list[dict]:
    matched: list[dict] = []
    for fn in fn_entries:
        if value in fn["code"]:
            matched.append({"name": fn["name"], "address": fn["address"]})
            if len(matched) >= limit:
                break
    return matched


def _clean_addr(addr: str) -> str:
    """Return normalised hex address string with Thumb LSB masked out."""
    try:
        n = int(addr, 16)
        n &= ~1  # mask Thumb bit
        return f"0x{n:08x}"
    except (ValueError, TypeError):
        return addr
