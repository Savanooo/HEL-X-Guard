"""Faz 7 — PDF report rendering.

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
    "medium":        "#eab308",
    "low":           "#22c55e",
    "informational": "#38bdf8",
}

_CATEGORY_COLORS = {
    "PRIVATE_KEY":     "#dc2626",
    "CERTIFICATE":     "#dc2626",
    "API_KEY":         "#f97316",
    "CREDENTIAL":      "#f97316",
    "SHELL_COMMAND":   "#eab308",
    "DEBUG_KEYWORD":   "#eab308",
    "URL":             "#0ea5e9",
    "IP":              "#0ea5e9",
    "DOMAIN":          "#0ea5e9",
    "NETWORK_SERVICE": "#0ea5e9",
}


def render_pdf(report: dict[str, Any], scan_meta: dict[str, Any] | None = None) -> bytes:
    """Render a report dict (firmware_scanner.report.build output) to a PDF.

    Raises RuntimeError if rendering fails.
    """
    scan_meta = scan_meta or {}
    risk_level = report.get("risk", {}).get("level", "informational")

    template = _env.get_template("report.html")
    html = template.render(
        report=report,
        scan=scan_meta,
        risk_color=_RISK_COLORS.get(risk_level, "#64748b"),
        cat_colors=_CATEGORY_COLORS,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    buffer = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if result.err:
        raise RuntimeError(f"PDF generation failed ({result.err} error(s))")
    return buffer.getvalue()
