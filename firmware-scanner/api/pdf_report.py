"""PDF report rendering for HELİX-Guard.

Uses xhtml2pdf (pure Python, no system libraries) rather than WeasyPrint —
WeasyPrint requires a GTK runtime (Pango/Cairo) that isn't pip-installable
on Windows. xhtml2pdf supports a constrained HTML/CSS subset, sufficient
for this report layout.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)

_RISK_COLORS = {
    "critical":      "#dc2626",
    "high":          "#f97316",
    "medium":        "#d97706",
    "low":           "#16a34a",
    "informational": "#0284c7",
}

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]

_CATEGORY_COLORS = {
    "PRIVATE_KEY":     "#dc2626",
    "CERTIFICATE":     "#dc2626",
    "SAFETY_BYPASS":   "#dc2626",
    "API_KEY":         "#ea580c",
    "CREDENTIAL":      "#ea580c",
    "WIFI_CREDENTIAL": "#ea580c",
    "FLASH_WRITE":     "#ea580c",
    "BOOTLOADER":      "#ea580c",
    "SHELL_COMMAND":   "#d97706",
    "DEBUG_KEYWORD":   "#d97706",
    "CRYPTO":          "#d97706",
    "MQTT_BROKER":     "#d97706",
    "AT_COMMAND":      "#d97706",
    "URL":             "#0284c7",
    "IP":              "#0284c7",
    "DOMAIN":          "#0284c7",
    "NETWORK_SERVICE": "#0284c7",
    "FILE_PATH":       "#475569",
    "VERSION":         "#475569",
}

_SEV_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#16a34a",
    "low_info": "#0284c7",
}


def _yara_by_severity(yara: dict) -> list[dict]:
    """Sort YARA matches by severity (critical first)."""
    matches = list(yara.get("matches", []))
    def sev_rank(m: dict) -> int:
        s = (m.get("severity") or "low").lower()
        return _SEV_ORDER.index(s) if s in _SEV_ORDER else 99
    return sorted(matches, key=sev_rank)


def _strings_by_severity(strings: dict) -> list[dict]:
    """Sort suspicious strings by category severity."""
    _cat_rank = {
        "PRIVATE_KEY": 0, "CERTIFICATE": 0, "SAFETY_BYPASS": 0,
        "API_KEY": 1, "CREDENTIAL": 1, "WIFI_CREDENTIAL": 1,
        "FLASH_WRITE": 1, "BOOTLOADER": 1,
        "SHELL_COMMAND": 2, "DEBUG_KEYWORD": 2, "CRYPTO": 2,
        "MQTT_BROKER": 2, "AT_COMMAND": 2,
        "URL": 3, "IP": 3, "DOMAIN": 3, "NETWORK_SERVICE": 3,
        "FILE_PATH": 4, "VERSION": 5,
    }
    items = list(strings.get("suspicious", []))
    return sorted(items, key=lambda s: _cat_rank.get(s.get("category", ""), 99))


def _exec_summary_bullets(report: dict) -> list[str]:
    """Build a short executive summary as bullet strings."""
    bullets = []
    risk = report.get("risk", {})
    risk_level = (risk.get("level") or "informational").upper()
    score = risk.get("score", 0)
    bullets.append(f"Overall risk level: {risk_level} ({score}/100)")

    yara_count = len(report.get("yara", {}).get("matches", []))
    susp_count  = report.get("strings", {}).get("suspicious_count", 0)
    if yara_count:
        bullets.append(f"{yara_count} YARA rule match{'es' if yara_count != 1 else ''} detected")
    if susp_count:
        bullets.append(f"{susp_count} suspicious string{'s' if susp_count != 1 else ''} extracted")

    comp = report.get("components", {})
    comp_count = comp.get("count", 0)
    if comp_count:
        bullets.append(f"{comp_count} SBOM component{'s' if comp_count != 1 else ''} identified")

    compliance = report.get("compliance", {})
    cwe_count = len(compliance.get("summary", {}).get("cwe", []))
    if cwe_count:
        bullets.append(f"{cwe_count} unique CWE identifier{'s' if cwe_count != 1 else ''} mapped")

    elf = report.get("elf", {})
    if elf.get("is_elf"):
        sec = elf.get("security", {})
        issues = []
        if not sec.get("nx", True):     issues.append("NX disabled")
        if not sec.get("pie", True):    issues.append("no PIE")
        relro = sec.get("relro", "full")
        if relro == "none":             issues.append("no RELRO")
        elif relro == "partial":        issues.append("partial RELRO")
        if issues:
            bullets.append("ELF hardening gaps: " + ", ".join(issues))

    entropy = report.get("entropy", {}).get("overall", 0.0)
    if entropy > 7.5:
        bullets.append(f"High entropy detected ({entropy:.2f}/8.00) — possible encryption or packing")

    return bullets


def render_pdf(report: dict[str, Any], scan_meta: dict[str, Any] | None = None) -> bytes:
    """Render a completed scan report dict to a PDF byte string.

    *scan_meta* may contain ``created_at``, ``completed_at``, ``filename``.
    Raises RuntimeError if PDF rendering fails.
    """
    scan_meta = scan_meta or {}
    risk_level  = (report.get("risk", {}).get("level") or "informational").lower()
    risk_color  = _RISK_COLORS.get(risk_level, "#64748b")
    risk_score  = report.get("risk", {}).get("score", 0)
    risk_label  = risk_level.upper()

    # Build derived data for template
    yara_sorted    = _yara_by_severity(report.get("yara", {}))
    strings_sorted = _strings_by_severity(report.get("strings", {}))
    exec_bullets   = _exec_summary_bullets(report)

    compliance     = report.get("compliance", {})
    comp_mappings  = compliance.get("mappings", []) if isinstance(compliance, dict) else []
    comp_summary   = compliance.get("summary", {}) if isinstance(compliance, dict) else {}
    has_compliance = bool(comp_mappings)

    components  = report.get("components", {}).get("components", [])
    has_sbom    = bool(components)

    template = _env.get_template("report.html")
    html = template.render(
        report=report,
        scan=scan_meta,
        risk_color=risk_color,
        risk_label=risk_label,
        risk_score=risk_score,
        cat_colors=_CATEGORY_COLORS,
        sev_colors=_SEV_COLORS,
        yara_sorted=yara_sorted,
        strings_sorted=strings_sorted,
        exec_bullets=exec_bullets,
        has_compliance=has_compliance,
        comp_mappings=comp_mappings[:50],
        comp_summary=comp_summary,
        has_sbom=has_sbom,
        components=components,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    buffer = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if result.err:
        raise RuntimeError(f"PDF generation failed ({result.err} error(s))")
    return buffer.getvalue()
