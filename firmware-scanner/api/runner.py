"""Scan execution — runs in a daemon thread (Faz 4) or as a Celery task (Faz 5).

  POST /api/v1/scans → save file → insert Scan(status=pending) → dispatch → 202
  Worker: status=running → resolve stored_path to a local file → run scanner
          → status=completed|failed → discard temp copy if object storage is used
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .database import SessionLocal
from .models import Scan
from . import storage

# Path to the bundled YARA rules — resolved relative to the project root
_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "firmware_rules.yar"


# ── Local (non-Docker) scan ───────────────────────────────────────────────────

def _run_local(firmware_path: Path) -> dict:
    """Run the scanner directly in the current process (no Docker)."""
    from firmware_scanner import (
        binwalk_runner,
        elf_analysis,
        entropy,
        hashing,
        report,
        risk_scoring,
        strings_scan,
        yara_runner,
    )

    rules_path = _RULES_PATH if _RULES_PATH.exists() else None

    hash_r    = hashing.hash_file(firmware_path)
    entropy_r = entropy.analyze(firmware_path)
    strings_r = strings_scan.scan(firmware_path)
    binwalk_r = binwalk_runner.scan(firmware_path)
    yara_r    = yara_runner.scan(firmware_path, rules_path=rules_path) if rules_path else {"matches": [], "error": None}
    elf_r     = elf_analysis.analyze(firmware_path)
    risk_r    = risk_scoring.score(entropy_r, strings_r, yara_r, binwalk_r, elf_r)

    return report.build(firmware_path, hash_r, entropy_r, strings_r, binwalk_r, yara_r, risk_r, elf_r)


# ── Docker scan ───────────────────────────────────────────────────────────────

def _run_docker(firmware_path: Path, output_dir: Path) -> dict:
    from firmware_scanner.sandbox import run_in_docker
    return run_in_docker(
        firmware_path,
        output_dir,
        image=settings.docker_image,
        memory=settings.docker_memory,
        cpus=settings.docker_cpus,
        timeout=settings.scan_timeout,
    )


# ── Background thread / Celery task body ──────────────────────────────────────

def _run_scan(scan_id: str, stored_path: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.status = "running"
        db.commit()

        local_path, is_temp = storage.resolve_for_analysis(stored_path)
        try:
            output_dir = storage.get_output_dir(scan_id)

            if settings.use_docker_sandbox:
                try:
                    result = _run_docker(local_path, output_dir)
                except Exception:
                    # Fall back to local scan if Docker fails
                    result = _run_local(local_path)
            else:
                result = _run_local(local_path)
        finally:
            storage.cleanup_temp(local_path, is_temp)

        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status       = "completed"
            scan.sha256       = result.get("file", {}).get("hashes", {}).get("sha256")
            scan.risk_score   = result.get("risk", {}).get("score")
            scan.risk_level   = result.get("risk", {}).get("level")
            scan.report_json  = json.dumps(result, ensure_ascii=False)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status        = "failed"
                scan.error_message = str(exc)
                scan.completed_at  = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def start_scan_thread(scan_id: str, stored_path: str) -> None:
    """Spawn a daemon thread to run the scan."""
    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, stored_path),
        daemon=True,
        name=f"scan-{scan_id[:8]}",
    )
    t.start()


# ── Extraction (Faz 2 deep analysis) ──────────────────────────────────────────

def _run_extraction(scan_id: str, stored_path: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.extraction_status = "running"
        db.commit()

        from firmware_scanner import binwalk_runner

        local_path, is_temp = storage.resolve_for_analysis(stored_path)
        try:
            out_dir = storage.get_output_dir(scan_id) / "extracted"
            result = binwalk_runner.extract(local_path, out_dir)
        finally:
            storage.cleanup_temp(local_path, is_temp)

        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.extraction_status = "failed" if result.get("error") else "completed"
            scan.extraction_json   = json.dumps(result, ensure_ascii=False)
            scan.extraction_error  = result.get("error")
            db.commit()

    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.extraction_status = "failed"
                scan.extraction_error  = str(exc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def start_extraction_thread(scan_id: str, stored_path: str) -> None:
    """Spawn a daemon thread to run binwalk extraction (extracted files are
    listed only — never executed)."""
    t = threading.Thread(
        target=_run_extraction,
        args=(scan_id, stored_path),
        daemon=True,
        name=f"extract-{scan_id[:8]}",
    )
    t.start()


# ── Decompilation (optional, heavy) ───────────────────────────────────────────

def _run_decompile(scan_id: str, stored_path: str,
                   processor: str | None = None,
                   base_address: str | None = None) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.decompile_status = "running"
        db.commit()

        from firmware_scanner import ghidra_runner

        local_path, is_temp = storage.resolve_for_analysis(stored_path)
        try:
            out_dir = storage.get_output_dir(scan_id) / "decompiled"
            result = ghidra_runner.decompile(local_path, out_dir,
                                             processor=processor,
                                             base_address=base_address)
        finally:
            storage.cleanup_temp(local_path, is_temp)

        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.decompile_status = "failed" if result.get("error") else "completed"
            scan.decompile_json   = json.dumps(result, ensure_ascii=False)
            scan.decompile_error  = result.get("error")
            db.commit()

    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.decompile_status = "failed"
                scan.decompile_error  = str(exc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def start_decompile_thread(scan_id: str, stored_path: str,
                           processor: str | None = None,
                           base_address: str | None = None) -> None:
    """Spawn a daemon thread to run Ghidra headless decompilation."""
    t = threading.Thread(
        target=_run_decompile,
        args=(scan_id, stored_path, processor, base_address),
        daemon=True,
        name=f"decompile-{scan_id[:8]}",
    )
    t.start()


# ── Dispatch (Faz 5 — Celery when enabled, thread otherwise) ─────────────────
#
# Routers call these instead of the start_*_thread functions directly, so
# switching HELIX_USE_CELERY doesn't require touching the API layer.
# stored_path is always a string — a local path or a MinIO object key,
# resolved to a real file lazily inside the worker (see storage.py).

def dispatch_scan(scan_id: str, stored_path: str) -> None:
    if settings.use_celery:
        from .tasks import run_scan_task
        run_scan_task.delay(scan_id, stored_path)
    else:
        start_scan_thread(scan_id, stored_path)


def dispatch_extraction(scan_id: str, stored_path: str) -> None:
    if settings.use_celery:
        from .tasks import run_extraction_task
        run_extraction_task.delay(scan_id, stored_path)
    else:
        start_extraction_thread(scan_id, stored_path)


def dispatch_decompile(scan_id: str, stored_path: str,
                       processor: str | None = None,
                       base_address: str | None = None) -> None:
    if settings.use_celery:
        from .tasks import run_decompile_task
        run_decompile_task.delay(scan_id, stored_path, processor, base_address)
    else:
        start_decompile_thread(scan_id, stored_path, processor, base_address)
