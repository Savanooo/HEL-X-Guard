"""Firmware version tracking and regression analysis.

Endpoints:
  GET  /api/v1/firmware/series          — list scans in a device lineage
  GET  /api/v1/firmware/regression/{a}/{b} — diff two scans for appeared/removed findings
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from ..auth import require_viewer
from ..database import get_db
from ..models import Scan, User
from ..audit import log_action

router = APIRouter(prefix="/api/v1/firmware", tags=["firmware"])

# ── helpers ───────────────────────────────────────────────────────────────────

_EXT_RE   = re.compile(r"\.(bin|hex|srec|uf2|elf|fw|img|s19|s37|ihex|out)$", re.I)
_VER_RE   = re.compile(r"[_\-]v?\d[\d.]*([_\-]rc\d*)?$", re.I)


def _stem(filename: str) -> str:
    """Strip extension and trailing version suffix from a firmware filename."""
    s = _EXT_RE.sub("", filename)
    s = _VER_RE.sub("", s)
    return s.lower().strip()


def _scan_to_meta(scan: Scan, report: dict[str, Any]) -> dict:
    return {
        "id":            scan.id,
        "filename":      scan.filename,
        "device_label":  scan.device_label,
        "risk_score":    scan.risk_score,
        "risk_level":    scan.risk_level,
        "created_at":    scan.created_at.isoformat() if scan.created_at else None,
        "completed_at":  scan.completed_at.isoformat() if scan.completed_at else None,
        "entropy":       report.get("entropy", {}).get("overall"),
        "file_size":     scan.file_size,
        "yara_count":    len(report.get("yara", {}).get("matches", [])),
        "suspicious_count": report.get("strings", {}).get("suspicious_count", 0),
        "sha256":        scan.sha256,
    }


def _yara_set(report: dict) -> set[str]:
    return {m.get("rule", "") for m in report.get("yara", {}).get("matches", [])}


def _string_set(report: dict) -> set[tuple[str, str]]:
    return {
        (s.get("value", ""), s.get("category", ""))
        for s in report.get("strings", {}).get("suspicious", [])
    }


# ── series endpoint ───────────────────────────────────────────────────────────

@router.get("/series", summary="Firmware version series for a device")
def get_series(
    request: Request,
    stem: str | None = Query(None, description="Filename stem (e.g. 'firmware_v') to match"),
    device_label: str | None = Query(None, description="Explicit device_label filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> dict:
    """Return all completed scans that belong to the same device lineage.

    Scans are grouped by ``device_label`` when set, otherwise by filename stem.
    Results are ordered oldest-first for trend display.
    """
    if not stem and not device_label:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide at least one of: stem, device_label",
        )

    query = db.query(Scan).filter(Scan.status == "completed")

    if device_label:
        query = query.filter(Scan.device_label == device_label)
    elif stem:
        query = query.filter(Scan.filename.ilike(f"{stem}%"))

    scans = query.order_by(Scan.created_at).all()

    # When filtering by stem only, post-filter to scans whose computed stem matches
    if stem and not device_label:
        scans = [s for s in scans if _stem(s.filename) == _stem(stem)]

    items = []
    for scan in scans:
        report: dict = json.loads(scan.report_json) if scan.report_json else {}
        items.append(_scan_to_meta(scan, report))

    log_action(
        db, action="view_firmware_series", user=current_user,
        resource_type="firmware", detail=f"stem={stem} device_label={device_label}",
        request=request,
    )

    return {"items": items, "count": len(items)}


# ── regression endpoint ───────────────────────────────────────────────────────

@router.get(
    "/regression/{scan_a_id}/{scan_b_id}",
    summary="Regression diff between two firmware scans",
)
def get_regression(
    scan_a_id: str,
    scan_b_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> dict:
    """Compare two completed scans and return appeared/removed security findings.

    *scan_a* is the baseline (older); *scan_b* is the candidate (newer).
    """
    scan_a = db.get(Scan, scan_a_id)
    scan_b = db.get(Scan, scan_b_id)

    for s, label in ((scan_a, "scan_a"), (scan_b, "scan_b")):
        if s is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{label} not found",
            )
        if s.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{label} is not completed (status={s.status})",
            )
        if not s.report_json:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{label} has no report data",
            )

    report_a: dict = json.loads(scan_a.report_json)   # type: ignore[union-attr]
    report_b: dict = json.loads(scan_b.report_json)   # type: ignore[union-attr]

    yara_a = _yara_set(report_a)
    yara_b = _yara_set(report_b)
    yara_appeared = sorted(yara_b - yara_a)
    yara_resolved = sorted(yara_a - yara_b)

    str_a = _string_set(report_a)
    str_b = _string_set(report_b)
    strings_appeared = [
        {"value": v, "category": c} for v, c in sorted(str_b - str_a)
    ]
    strings_removed = [
        {"value": v, "category": c} for v, c in sorted(str_a - str_b)
    ]

    risk_a = scan_a.risk_score or 0.0
    risk_b = scan_b.risk_score or 0.0
    entropy_a = report_a.get("entropy", {}).get("overall", 0.0) or 0.0
    entropy_b = report_b.get("entropy", {}).get("overall", 0.0) or 0.0

    log_action(
        db, action="view_regression", user=current_user,
        resource_type="scan", resource_id=f"{scan_a_id}→{scan_b_id}",
        request=request,
    )

    return {
        "scan_a": _scan_to_meta(scan_a, report_a),
        "scan_b": _scan_to_meta(scan_b, report_b),
        "risk_delta":     round(risk_b - risk_a, 2),
        "entropy_delta":  round(entropy_b - entropy_a, 4),
        "yara_appeared":  yara_appeared,
        "yara_resolved":  yara_resolved,
        "strings_appeared": strings_appeared[:200],
        "strings_removed":  strings_removed[:200],
        "summary": {
            "risk_direction":   "worse" if risk_b > risk_a else ("better" if risk_b < risk_a else "unchanged"),
            "yara_new":         len(yara_appeared),
            "yara_resolved":    len(yara_resolved),
            "strings_appeared": len(strings_appeared),
            "strings_removed":  len(strings_removed),
        },
    }
