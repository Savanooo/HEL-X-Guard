"""Faz 5 — Celery application definition.

Only imported when HELIX_USE_CELERY=true. Run a worker with:
    celery -A api.celery_app worker --loglevel=info --pool=solo   (Windows)
    celery -A api.celery_app worker --loglevel=info               (Linux/macOS)
"""
from __future__ import annotations

from celery import Celery

from .config import settings

celery_app = Celery(
    "helix_guard",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["api.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Long-running static analysis: don't let the broker think the worker
    # vanished mid-scan.
    broker_connection_retry_on_startup=True,
    task_time_limit=1800,
)
