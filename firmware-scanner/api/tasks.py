"""Faz 5 — Celery task wrappers around the runner's analysis functions.

Each task is a thin shim: Celery can only pass JSON-serializable arguments,
which stored_path already is (a local path string or a MinIO object key) —
the underlying functions in runner.py are shared between thread and Celery
execution and resolve it to a real file via storage.resolve_for_analysis().
"""
from __future__ import annotations

from .celery_app import celery_app
from . import runner


@celery_app.task(name="helix.run_scan", bind=True)
def run_scan_task(self, scan_id: str, stored_path: str) -> None:
    runner._run_scan(scan_id, stored_path)


@celery_app.task(name="helix.run_extraction", bind=True)
def run_extraction_task(self, scan_id: str, stored_path: str) -> None:
    runner._run_extraction(scan_id, stored_path)


@celery_app.task(name="helix.run_decompile", bind=True)
def run_decompile_task(self, scan_id: str, stored_path: str) -> None:
    runner._run_decompile(scan_id, stored_path)
