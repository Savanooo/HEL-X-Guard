"""Scan CRUD endpoints — upload firmware, poll status, retrieve reports."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import require_analyst, require_viewer
from ..database import get_db
from ..models import Scan, User
from ..runner import dispatch_cve, dispatch_decompile, dispatch_disasm, dispatch_extraction, dispatch_scan
from ..schemas import DecompileRequest, DisasmRequest, ScanDetailResponse, ScanDiffResponse, ScanListResponse, ScanResponse
from .. import storage

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_scan(
    scan_id: str,
    current_user: User,
    db: Session,
    *,
    request: Request | None = None,
    action: str = "access_scan",
) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if current_user.role != "admin" and scan.user_id != current_user.id:
        log_action(
            db, action=action, user=current_user, resource_type="scan",
            resource_id=scan_id, success=False, detail="Forbidden — not owner",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return scan


def _to_detail(scan: Scan) -> ScanDetailResponse:
    detail = ScanDetailResponse.model_validate(scan)
    if scan.report_json:
        detail.report = json.loads(scan.report_json)
    if scan.extraction_json:
        detail.extraction = json.loads(scan.extraction_json)
    if scan.decompile_json:
        detail.decompile = json.loads(scan.decompile_json)
    if scan.cve_json:
        detail.cve = json.loads(scan.cve_json)
    if scan.disasm_json:
        detail.disasm = json.loads(scan.disasm_json)
    # Rootfs is stored inside extraction_json["rootfs"] (Feature 5)
    if detail.extraction and isinstance(detail.extraction.get("rootfs"), dict):
        detail.rootfs = detail.extraction["rootfs"]
    # Call graph is stored inside decompile_json["call_graph"] (Feature 6)
    if detail.decompile and isinstance(detail.decompile.get("call_graph"), dict):
        detail.call_graph = detail.decompile["call_graph"]
    return detail


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
    summary="Upload firmware and start analysis",
)
async def create_scan(
    request: Request,
    file: UploadFile = File(..., description="Binary firmware file"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Scan:
    """Upload a firmware file, create a scan record (status=pending), and kick off
    analysis in a background thread. Returns the scan_id for polling."""
    scan_id = str(uuid.uuid4())

    stored_path, file_size = await storage.save_upload(scan_id, file)

    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        filename=file.filename or Path(stored_path).name,
        file_size=file_size,
        stored_path=stored_path,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_action(
        db, action="create_scan", user=current_user, resource_type="scan",
        resource_id=scan_id, detail=scan.filename, request=request,
    )

    dispatch_scan(scan_id, stored_path)

    return scan


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List scans with pagination and filters",
)
def list_scans(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    scan_status: str | None = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ScanListResponse:
    q = db.query(Scan)
    if current_user.role != "admin":
        q = q.filter(Scan.user_id == current_user.id)
    if risk_level:
        q = q.filter(Scan.risk_level == risk_level)
    if scan_status:
        q = q.filter(Scan.status == scan_status)

    total = q.count()
    items = (
        q.order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return ScanListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan status and result",
)
def get_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ScanDetailResponse:
    scan = _get_scan(scan_id, current_user, db, request=request, action="view_scan")
    return _to_detail(scan)


@router.get(
    "/{scan_id}/report",
    summary="Full JSON analysis report",
)
def get_report(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> dict:
    scan = _get_scan(scan_id, current_user, db, request=request, action="view_report")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail=f"Scan is '{scan.status}' — wait for 'completed'",
        )
    if not scan.report_json:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not available")

    log_action(
        db, action="view_report", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )
    return json.loads(scan.report_json)


@router.get(
    "/{scan_id}/report.pdf",
    summary="PDF analysis report",
)
def get_report_pdf(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Response:
    scan = _get_scan(scan_id, current_user, db, request=request, action="view_report_pdf")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail=f"Scan is '{scan.status}' — wait for 'completed'",
        )
    if not scan.report_json:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not available")

    from .. import pdf_report

    report = json.loads(scan.report_json)
    scan_meta = {
        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else None,
        "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else None,
    }

    try:
        pdf_bytes = pdf_report.render_pdf(report, scan_meta)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {exc}",
        )

    log_action(
        db, action="view_report_pdf", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )

    safe_name = (scan.filename or scan_id).rsplit(".", 1)[0]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="helix-report-{safe_name}.pdf"'},
    )


@router.post(
    "/{scan_id}/extract",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanDetailResponse,
    summary="Trigger binwalk extraction (Faz 2 deep analysis)",
)
def trigger_extract(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> ScanDetailResponse:
    """Re-run the firmware through binwalk's extraction mode. Extracted files
    are listed in the result but are NEVER executed."""
    scan = _get_scan(scan_id, current_user, db, request=request, action="trigger_extract")

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial scan must complete before extraction can run",
        )
    if scan.extraction_status in ("pending", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Extraction already in progress")
    if not scan.stored_path or not storage.exists(scan.stored_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Original firmware file is no longer available",
        )

    scan.extraction_status = "pending"
    scan.extraction_json = None
    scan.extraction_error = None
    db.commit()
    db.refresh(scan)

    log_action(
        db, action="trigger_extract", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )

    dispatch_extraction(scan_id, scan.stored_path)
    return _to_detail(scan)


@router.post(
    "/{scan_id}/decompile",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanDetailResponse,
    summary="Trigger Ghidra headless decompilation (optional, heavy)",
)
def trigger_decompile(
    scan_id: str,
    request: Request,
    body: DecompileRequest = DecompileRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> ScanDetailResponse:
    """Run Ghidra headless analysis to produce decompiled pseudocode.

    Requires GHIDRA_HOME to be configured on the server; returns 501 if
    Ghidra is not installed. The firmware is statically disassembled and
    never executed."""
    scan = _get_scan(scan_id, current_user, db, request=request, action="trigger_decompile")

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial scan must complete before decompilation can run",
        )
    if scan.decompile_status in ("pending", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Decompilation already in progress")

    from firmware_scanner import ghidra_runner

    if not ghidra_runner.is_available():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Ghidra is not configured on this server (set GHIDRA_HOME)",
        )
    if not scan.stored_path or not storage.exists(scan.stored_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Original firmware file is no longer available",
        )

    scan.decompile_status = "pending"
    scan.decompile_json = None
    scan.decompile_error = None
    db.commit()
    db.refresh(scan)

    log_action(
        db, action="trigger_decompile", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )

    dispatch_decompile(scan_id, scan.stored_path,
                       processor=body.processor,
                       base_address=body.base_address)
    return _to_detail(scan)


@router.get(
    "/{scan_id_a}/diff/{scan_id_b}",
    response_model=ScanDiffResponse,
    summary="Compare two completed scans — strings, YARA, risk delta",
)
def diff_scans(
    scan_id_a: str,
    scan_id_b: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> dict:
    scan_a = _get_scan(scan_id_a, current_user, db, request=request, action="diff_scan")
    scan_b = _get_scan(scan_id_b, current_user, db, request=request, action="diff_scan")

    for s in (scan_a, scan_b):
        if s.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Scan {s.id} ({s.filename}) is not completed",
            )
        if not s.report_json:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No report available for scan {s.id}",
            )

    report_a = json.loads(scan_a.report_json)
    report_b = json.loads(scan_b.report_json)

    # ── String diff (by value + category key) ─────────────────────────────
    def _string_map(report: dict) -> dict[tuple[str, str], dict]:
        return {
            (s["value"], s["category"]): s
            for s in report.get("strings", {}).get("suspicious", [])
        }

    smap_a = _string_map(report_a)
    smap_b = _string_map(report_b)
    keys_added   = set(smap_b) - set(smap_a)
    keys_removed = set(smap_a) - set(smap_b)

    strings_added   = sorted([smap_b[k] for k in keys_added],   key=lambda x: x.get("category", ""))
    strings_removed = sorted([smap_a[k] for k in keys_removed], key=lambda x: x.get("category", ""))

    # ── YARA diff (by rule name) ───────────────────────────────────────────
    def _yara_map(report: dict) -> dict[str, dict]:
        return {m["rule"]: m for m in report.get("yara", {}).get("matches", [])}

    ymap_a = _yara_map(report_a)
    ymap_b = _yara_map(report_b)
    yara_new      = [ymap_b[r] for r in ymap_b if r not in ymap_a]
    yara_resolved = [ymap_a[r] for r in ymap_a if r not in ymap_b]

    # ── Numeric deltas ─────────────────────────────────────────────────────
    risk_a    = float(report_a.get("risk", {}).get("score", 0))
    risk_b    = float(report_b.get("risk", {}).get("score", 0))
    entropy_a = float(report_a.get("entropy", {}).get("overall", 0))
    entropy_b = float(report_b.get("entropy", {}).get("overall", 0))
    size_delta = (
        (scan_b.file_size - scan_a.file_size)
        if scan_a.file_size is not None and scan_b.file_size is not None
        else None
    )

    return {
        "scan_a": {
            "id": scan_a.id, "filename": scan_a.filename,
            "risk_score": risk_a, "risk_level": scan_a.risk_level,
            "created_at": scan_a.created_at, "entropy": entropy_a,
            "file_size": scan_a.file_size,
            "suspicious_count": len(smap_a), "yara_count": len(ymap_a),
        },
        "scan_b": {
            "id": scan_b.id, "filename": scan_b.filename,
            "risk_score": risk_b, "risk_level": scan_b.risk_level,
            "created_at": scan_b.created_at, "entropy": entropy_b,
            "file_size": scan_b.file_size,
            "suspicious_count": len(smap_b), "yara_count": len(ymap_b),
        },
        "summary": {
            "risk_delta": round(risk_b - risk_a, 1),
            "entropy_delta": round(entropy_b - entropy_a, 4),
            "file_size_delta": size_delta,
            "strings_added": len(strings_added),
            "strings_removed": len(strings_removed),
            "yara_new": len(yara_new),
            "yara_resolved": len(yara_resolved),
        },
        "strings_added":   strings_added[:300],
        "strings_removed": strings_removed[:300],
        "yara_new":        yara_new,
        "yara_resolved":   yara_resolved,
    }


@router.post(
    "/{scan_id}/analyze/cve",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanDetailResponse,
    summary="Trigger CVE cross-reference against detected components (Tier 2)",
)
def trigger_cve(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> ScanDetailResponse:
    """Cross-reference the SBOM detected by components.py against the offline
    CVE database (rules/cve_db.json). Requires a completed scan."""
    scan = _get_scan(scan_id, current_user, db, request=request, action="trigger_cve")

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial scan must complete before CVE match can run",
        )
    if scan.cve_status in ("pending", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="CVE match already in progress")
    if not scan.report_json:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not available")

    scan.cve_status = "pending"
    scan.cve_json   = None
    scan.cve_error  = None
    db.commit()
    db.refresh(scan)

    log_action(
        db, action="trigger_cve", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )

    dispatch_cve(scan_id)
    return _to_detail(scan)


@router.post(
    "/{scan_id}/analyze/disasm",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanDetailResponse,
    summary="Trigger capstone instruction histogram analysis (Tier 2)",
)
def trigger_disasm(
    scan_id: str,
    request: Request,
    body: DisasmRequest = DisasmRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> ScanDetailResponse:
    """Run capstone-based disassembly statistics on the firmware.
    Returns instruction histogram, suspicious instruction list, and a
    cheap function count estimate. Never executes the binary."""
    scan = _get_scan(scan_id, current_user, db, request=request, action="trigger_disasm")

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Initial scan must complete before disassembly can run",
        )
    if scan.disasm_status in ("pending", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Disassembly already in progress")
    if not scan.stored_path or not storage.exists(scan.stored_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Original firmware file is no longer available",
        )

    scan.disasm_status = "pending"
    scan.disasm_json   = None
    scan.disasm_error  = None
    db.commit()
    db.refresh(scan)

    log_action(
        db, action="trigger_disasm", user=current_user, resource_type="scan",
        resource_id=scan_id, request=request,
    )

    dispatch_disasm(scan_id, scan.stored_path, arch=body.arch)
    return _to_detail(scan)


_MAX_FN_BYTES = 4096  # 4 KB ceiling for per-function disasm slice


@router.get(
    "/{scan_id}/function/disasm",
    summary="On-demand capstone Thumb-2 disassembly for a single decompiled function",
)
def get_function_disasm(
    scan_id: str,
    request: Request,
    addr: str = Query(..., description="Function entry address from decompile results (e.g. '0800a098')"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> list[dict]:
    """Disassemble one function's byte range from the stored firmware using capstone.

    Size is inferred from the gap to the next function in decompile_json (capped at
    4 KB). No new Ghidra run occurs — only the stored binary is read, never executed.
    """
    scan = _get_scan(scan_id, current_user, db, request=request, action="view_function_disasm")

    if scan.decompile_status != "completed" or not scan.decompile_json:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decompilation results are not available for this scan",
        )
    if not scan.stored_path or not storage.exists(scan.stored_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Original firmware file is no longer available",
        )

    # Parse target address — handles both "0800a098" (Ghidra) and "0x0800a098"
    try:
        target_addr = int(addr.strip(), 16)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid address value: {addr!r}",
        )

    decompile_data = json.loads(scan.decompile_json)
    all_fns: list[dict] = decompile_data.get("functions", [])

    # Collect all function addresses as integers
    fn_int_addrs: list[int] = []
    for fn in all_fns:
        try:
            fn_int_addrs.append(int(fn["address"], 16))
        except (ValueError, KeyError, TypeError):
            pass

    if target_addr not in fn_int_addrs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Function at 0x{target_addr:08x} not found in decompile results",
        )

    # Size = gap to next function address, capped at _MAX_FN_BYTES
    sorted_addrs = sorted(set(fn_int_addrs))
    try:
        idx = sorted_addrs.index(target_addr)
        if idx + 1 < len(sorted_addrs):
            fn_size = min(sorted_addrs[idx + 1] - target_addr, _MAX_FN_BYTES)
        else:
            fn_size = _MAX_FN_BYTES
    except ValueError:
        fn_size = _MAX_FN_BYTES
    fn_size = max(fn_size, 2)

    # Load address + capstone arch from arch info in the main report
    load_addr = 0x0800_0000  # STM32 flash default
    arch_info: dict = {}
    if scan.report_json:
        arch_info = json.loads(scan.report_json).get("arch", {})
        raw_la = arch_info.get("inferred_load_address")
        if raw_la is not None:
            try:
                load_addr = int(str(raw_la), 16)
            except (ValueError, TypeError):
                pass

    file_offset = target_addr - load_addr
    if file_offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Function address 0x{target_addr:08x} is below "
                f"load address 0x{load_addr:08x}"
            ),
        )

    # Read the relevant byte slice from firmware (read-only, never executed)
    local_path, is_temp = storage.resolve_for_analysis(scan.stored_path)
    try:
        fw_data = local_path.read_bytes()
    finally:
        storage.cleanup_temp(local_path, is_temp)

    end_offset = min(file_offset + fn_size, len(fw_data))
    fn_bytes = fw_data[file_offset:end_offset]
    if not fn_bytes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No firmware bytes available at that address range",
        )

    # Disassemble with capstone — use detected arch, fall back to Thumb-2
    try:
        import capstone
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="capstone is not installed on this server — pip install capstone",
        )

    cap_arch = capstone.CS_ARCH_ARM   # default: ARM Thumb (Cortex-M)
    cap_mode = capstone.CS_MODE_THUMB
    # arch_info already extracted above for load_addr; reuse it for arch detection
    _raw_arch = arch_info.get("capstone_arch")
    _raw_mode = arch_info.get("capstone_mode")
    if _raw_arch is not None and _raw_mode is not None:
        try:
            cap_arch = int(_raw_arch)
            cap_mode = int(_raw_mode)
        except (TypeError, ValueError):
            pass

    md = capstone.Cs(cap_arch, cap_mode)
    md.detail   = False
    md.skipdata = True

    instructions: list[dict] = []
    for insn in md.disasm(fn_bytes, target_addr):
        if insn.mnemonic.startswith("."):   # skip .byte / .short skipdata placeholders
            continue
        instructions.append({
            "addr":     f"0x{insn.address:08x}",
            "bytes":    insn.bytes.hex(" "),
            "mnemonic": insn.mnemonic,
            "op_str":   insn.op_str,
        })

    log_action(
        db, action="view_function_disasm", user=current_user, resource_type="scan",
        resource_id=scan_id, detail=f"addr=0x{target_addr:08x}", request=request,
    )
    return instructions


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan record (admin or owner)",
)
def delete_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> None:
    scan = _get_scan(scan_id, current_user, db, request=request, action="delete_scan")
    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete a running scan",
        )
    filename, stored_path = scan.filename, scan.stored_path
    db.delete(scan)
    db.commit()
    storage.cleanup_scan(scan_id, stored_path)

    log_action(
        db, action="delete_scan", user=current_user, resource_type="scan",
        resource_id=scan_id, detail=filename, request=request,
    )
