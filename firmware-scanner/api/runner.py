"""Scan execution — runs in a daemon thread (Faz 4) or as a Celery task (Faz 5).

  POST /api/v1/scans → save file → insert Scan(status=pending) → dispatch → 202
  Worker: status=running → resolve stored_path to a local file → run scanner
          → status=completed|failed → discard temp copy if object storage is used
"""
from __future__ import annotations

import json
import tempfile
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

def _build_combined_rules(db) -> tuple[Path | None, bool]:
    """Return (rules_path, is_temp) for the combined YARA ruleset.

    Merges the built-in firmware_rules.yar with all enabled user-managed rules
    from the database.  Returns (built-in path, False) when no user rules are
    enabled, or (temp file path, True) when user rules are present.
    Caller is responsible for unlinking the temp file if is_temp is True.
    """
    from .models import YaraRule

    user_rules = (
        db.query(YaraRule)
        .filter(YaraRule.enabled.is_(True))
        .order_by(YaraRule.created_at)
        .all()
    )

    builtin_exists = _RULES_PATH.exists()

    if not user_rules:
        return (_RULES_PATH if builtin_exists else None), False

    # Write combined rules to a temp file
    parts: list[str] = []
    if builtin_exists:
        parts.append(_RULES_PATH.read_text(encoding="utf-8"))
    for rule in user_rules:
        parts.append(f"\n// User rule: {rule.name}\n{rule.content}\n")

    combined = "\n".join(parts)
    fd, tmp = tempfile.mkstemp(suffix=".yar", prefix="helix_combined_")
    import os as _os; _os.close(fd)
    tmp_path = Path(tmp)
    tmp_path.write_text(combined, encoding="utf-8")
    return tmp_path, True


def _run_local(
    firmware_path: Path,
    *,
    firmware_info: dict | None = None,
    display_name: str | None = None,
    rules_path: Path | None = None,
) -> dict:
    """Run the scanner directly in the current process (no Docker).

    *firmware_info* — optional metadata from firmware_loader (format, load address)
    *display_name*  — original filename to store in the report for HEX/SREC/UF2 uploads
    """
    from firmware_scanner import (
        arch_detect,
        binwalk_runner,
        cert_extract,
        checksec,
        components,
        crypto_constants,
        elf_analysis,
        entropy,
        hashing,
        report,
        risk_scoring,
        strings_scan,
        yara_runner,
    )

    # rules_path: caller supplies combined (built-in + user) rules path; fall back to built-in
    effective_rules = rules_path if rules_path is not None else (_RULES_PATH if _RULES_PATH.exists() else None)

    # Feed the known load address from HEX/SREC/UF2 records into arch_detect
    load_addr_override = (firmware_info or {}).get("load_address") or None

    # Tier 1 — always-on, fast
    hash_r    = hashing.hash_file(firmware_path)
    entropy_r = entropy.analyze(firmware_path)
    strings_r = strings_scan.scan(firmware_path)
    binwalk_r = binwalk_runner.scan(firmware_path)
    yara_r    = yara_runner.scan(firmware_path, rules_path=effective_rules) if effective_rules else {"matches": [], "error": None}
    elf_r     = elf_analysis.analyze(firmware_path)
    arch_r    = arch_detect.analyze(firmware_path, load_address_override=load_addr_override)
    checksec_r = checksec.analyze(firmware_path)
    crypto_r  = crypto_constants.analyze(firmware_path)
    comp_r    = components.analyze(firmware_path)
    cert_r    = cert_extract.analyze(firmware_path)

    risk_r = risk_scoring.score(
        entropy_r, strings_r, yara_r, binwalk_r, elf_r,
        checksec_result=checksec_r,
        cert_result=cert_r,
    )

    return report.build(
        firmware_path, hash_r, entropy_r, strings_r, binwalk_r, yara_r, risk_r,
        elf_result=elf_r,
        arch_result=arch_r,
        checksec_result=checksec_r,
        crypto_result=crypto_r,
        components_result=comp_r,
        cert_result=cert_r,
        firmware_info=firmware_info,
        display_name=display_name,
    )


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
        norm_path: Path | None = None
        try:
            output_dir = storage.get_output_dir(scan_id)

            # Normalize Intel HEX / SREC / UF2 → raw binary before analysis
            from firmware_scanner import firmware_loader
            try:
                fw_info_obj = firmware_loader.load(local_path)
            except Exception:
                fw_info_obj = None

            if fw_info_obj is not None and fw_info_obj.format_name != "raw":
                # Write normalised bytes to a temp .bin file
                fd, tmp = tempfile.mkstemp(suffix=".bin", prefix="helix_norm_")
                import os; os.close(fd)
                norm_path = Path(tmp)
                norm_path.write_bytes(fw_info_obj.raw_bytes)
                analysis_path  = norm_path
                firmware_info  = {
                    "original_format": fw_info_obj.format_name,
                    "load_address":    fw_info_obj.load_address,
                }
                display_name = local_path.name  # e.g. "firmware.hex"
            else:
                analysis_path = local_path
                firmware_info = None
                display_name  = None

            # Build combined YARA rules (built-in + enabled user rules from DB)
            combined_rules_path, combined_is_temp = _build_combined_rules(db)

            try:
                if settings.use_docker_sandbox:
                    try:
                        result = _run_docker(analysis_path, output_dir)
                    except Exception:
                        result = _run_local(
                            analysis_path,
                            firmware_info=firmware_info,
                            display_name=display_name,
                            rules_path=combined_rules_path,
                        )
                else:
                    result = _run_local(
                        analysis_path,
                        firmware_info=firmware_info,
                        display_name=display_name,
                        rules_path=combined_rules_path,
                    )
            finally:
                if combined_is_temp and combined_rules_path and combined_rules_path.exists():
                    try:
                        combined_rules_path.unlink()
                    except OSError:
                        pass
        finally:
            storage.cleanup_temp(local_path, is_temp)
            if norm_path and norm_path.exists():
                try:
                    norm_path.unlink()
                except OSError:
                    pass

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


# ── CVE match (Tier 2 opt-in) ─────────────────────────────────────────────────

def _run_cve_match(scan_id: str) -> None:
    """Run CVE cross-reference against detected components from an existing scan."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.cve_status = "running"
        db.commit()

        report_data = json.loads(scan.report_json) if scan.report_json else {}
        comp_r = report_data.get("components", {"components": [], "count": 0})

        from firmware_scanner import cve_match, risk_scoring
        result = cve_match.match(comp_r)

        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.cve_status = "failed" if result.get("error") else "completed"
            scan.cve_json   = json.dumps(result, ensure_ascii=False)
            scan.cve_error  = result.get("error")
            db.commit()

    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.cve_status = "failed"
                scan.cve_error  = str(exc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def start_cve_thread(scan_id: str) -> None:
    """Spawn a daemon thread to run CVE cross-reference."""
    t = threading.Thread(
        target=_run_cve_match,
        args=(scan_id,),
        daemon=True,
        name=f"cve-{scan_id[:8]}",
    )
    t.start()


# ── Disasm stats (Tier 2 opt-in) ──────────────────────────────────────────────

def _run_disasm(scan_id: str, stored_path: str, arch: str = "thumb") -> None:
    """Run capstone instruction histogram analysis."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.disasm_status = "running"
        db.commit()

        from firmware_scanner import disasm_stats

        arch_info = None
        if scan.report_json:
            arch_info = json.loads(scan.report_json).get("arch")

        local_path, is_temp = storage.resolve_for_analysis(stored_path)
        try:
            result = disasm_stats.analyze(local_path, arch_info=arch_info)
        finally:
            storage.cleanup_temp(local_path, is_temp)

        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.disasm_status = "failed" if result.get("error") else "completed"
            scan.disasm_json   = json.dumps(result, ensure_ascii=False)
            scan.disasm_error  = result.get("error")
            db.commit()

    except Exception as exc:  # noqa: BLE001
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.disasm_status = "failed"
                scan.disasm_error  = str(exc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def start_disasm_thread(scan_id: str, stored_path: str, arch: str = "thumb") -> None:
    """Spawn a daemon thread to run disassembly statistics."""
    t = threading.Thread(
        target=_run_disasm,
        args=(scan_id, stored_path, arch),
        daemon=True,
        name=f"disasm-{scan_id[:8]}",
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


def dispatch_cve(scan_id: str) -> None:
    start_cve_thread(scan_id)


def dispatch_disasm(scan_id: str, stored_path: str, arch: str = "thumb") -> None:
    start_disasm_thread(scan_id, stored_path, arch)
