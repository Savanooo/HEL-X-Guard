"""Map scan findings to compliance standards.

Standards covered:
  CWE        — Common Weakness Enumeration (MITRE)
  EU CRA     — Cyber Resilience Act Annex I (November 2024)
  IEC 62443  — IEC 62443-4-2 Component Security Requirements
  FDA        — FDA 2023 Cybersecurity Guidance for Medical Devices (§ 524B)
"""
from __future__ import annotations

import json
from pathlib import Path

_MAP_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "compliance_map.json"

_MAP: dict | None = None


def _load_map() -> dict:
    global _MAP
    if _MAP is None:
        _MAP = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
    return _MAP


def analyze(report: dict) -> dict:
    """Return compliance mappings derived from a completed scan report.

    Returns:
        {
          "mappings": [
            {
              "finding":   str,
              "source":    str,   # "yara:<rule>", "string:<category>", "condition:<key>"
              "cwe":       [str],
              "eu_cra":    [str],
              "iec_62443": [str],
              "fda":       [str],
            }
          ],
          "summary": {
            "cwe":       [str],   # union of all, sorted
            "eu_cra":    [str],
            "iec_62443": [str],
            "fda":       [str],
          },
          "error": None | str,
        }
    """
    try:
        return _do_analyze(report)
    except Exception as exc:
        empty: dict[str, list[str]] = {"cwe": [], "eu_cra": [], "iec_62443": [], "fda": []}
        return {"mappings": [], "summary": empty, "error": str(exc)}


def _do_analyze(report: dict) -> dict:
    cmap       = _load_map()
    mappings: list[dict] = []

    # ── YARA rule matches ────────────────────────────────────────────────────
    yara_rules_map = cmap.get("yara_rules", {})
    for match in report.get("yara", {}).get("matches", []):
        rule_name = match.get("rule", "")
        if rule_name in yara_rules_map:
            entry = yara_rules_map[rule_name]
            mappings.append(_make(f"yara:{rule_name}", entry["title"], entry))

    # ── String categories ────────────────────────────────────────────────────
    str_cat_map   = cmap.get("string_categories", {})
    cat_counts: dict[str, int] = report.get("strings", {}).get("category_counts") or {}
    if not cat_counts:
        for item in report.get("strings", {}).get("suspicious", []):
            cat = item.get("category", "")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    for cat, count in cat_counts.items():
        if count > 0 and cat in str_cat_map:
            entry  = str_cat_map[cat]
            plural = "s" if count != 1 else ""
            mappings.append(
                _make(f"string:{cat}",
                      f"{entry['title']} ({count} instance{plural})",
                      entry)
            )

    # ── ELF / checksec hardening conditions ──────────────────────────────────
    cond_map = cmap.get("conditions", {})

    elf      = report.get("elf", {})
    checksec = report.get("checksec", {})

    if elf.get("is_elf") and not elf.get("error"):
        sec = elf.get("security", {})
        if not sec.get("nx", True):
            _add_cond(mappings, cond_map, "no_nx")
        if not sec.get("pie", True):
            _add_cond(mappings, cond_map, "no_pie")
        relro = sec.get("relro", "full")
        if relro == "none":
            _add_cond(mappings, cond_map, "no_relro")
        elif relro == "partial":
            _add_cond(mappings, cond_map, "partial_relro")
        has_canary = "__stack_chk_fail" in (
            elf.get("imported_symbols", []) + elf.get("exported_symbols", [])
        )
        if not has_canary:
            _add_cond(mappings, cond_map, "no_stack_canary")

    elif checksec.get("is_elf") and not checksec.get("error"):
        if not checksec.get("nx", True):
            _add_cond(mappings, cond_map, "no_nx")
        if not checksec.get("pie", True):
            _add_cond(mappings, cond_map, "no_pie")
        relro = checksec.get("relro", "full")
        if relro == "none":
            _add_cond(mappings, cond_map, "no_relro")
        elif relro == "partial":
            _add_cond(mappings, cond_map, "partial_relro")
        if not checksec.get("canary", True):
            _add_cond(mappings, cond_map, "no_stack_canary")

    if report.get("entropy", {}).get("overall", 0.0) > 7.5:
        _add_cond(mappings, cond_map, "high_entropy")

    # ── Deduplicate by source ─────────────────────────────────────────────────
    seen: set[str] = set()
    unique: list[dict] = []
    for m in mappings:
        if m["source"] not in seen:
            seen.add(m["source"])
            unique.append(m)

    # ── Build summary (union of all referenced standards) ────────────────────
    summary: dict[str, list[str]] = {"cwe": [], "eu_cra": [], "iec_62443": [], "fda": []}
    seen_refs: dict[str, set[str]] = {k: set() for k in summary}
    for m in unique:
        for std in summary:
            for ref in m.get(std, []):
                if ref not in seen_refs[std]:
                    seen_refs[std].add(ref)
                    summary[std].append(ref)
    for std in summary:
        summary[std].sort()

    return {"mappings": unique, "summary": summary, "error": None}


def _make(source: str, title: str, entry: dict) -> dict:
    return {
        "finding":   title,
        "source":    source,
        "cwe":       list(entry.get("cwe", [])),
        "eu_cra":    list(entry.get("eu_cra", [])),
        "iec_62443": list(entry.get("iec_62443", [])),
        "fda":       list(entry.get("fda", [])),
    }


def _add_cond(mappings: list, cond_map: dict, key: str) -> None:
    entry = cond_map.get(key)
    if entry:
        mappings.append(_make(f"condition:{key}", entry["title"], entry))
