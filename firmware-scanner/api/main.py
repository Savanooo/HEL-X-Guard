"""HELİX-Guard FastAPI application entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import hash_password
from .config import settings
from .database import SessionLocal
from .models import User
from .routers import audit as audit_router
from .routers import auth as auth_router
from .routers import firmware as firmware_router
from .routers import rules as rules_router
from .routers import scans as scans_router

log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_migrations() -> None:
    """Apply all pending Alembic migrations (Faz 6 — versioned schema,
    works identically against SQLite and PostgreSQL)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(_PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_PROJECT_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


def _bootstrap_db() -> None:
    """Apply migrations and seed the default admin account on first run."""
    _run_migrations()

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == settings.admin_username).first():
            admin = User(
                username=settings.admin_username,
                email=settings.admin_email,
                role="admin",
                hashed_password=hash_password(settings.admin_password),
            )
            db.add(admin)
            db.commit()
            log.info("Default admin account created: %s", settings.admin_username)
    finally:
        db.close()


def _recover_orphans() -> None:
    """Mark scans left in 'running' state by a previous crash as 'failed'.

    Called once at startup before the API starts accepting requests.  Any
    scan (or sub-task) whose status is still 'running' was interrupted by a
    server restart or OOM-kill — it will never complete on its own, so we
    flip it to 'failed' so the UI doesn't show it as spinning forever.
    """
    from .models import Scan

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        msg = "interrupted (server restart/OOM)"

        for scan in db.query(Scan).filter(Scan.status == "running").all():
            scan.status        = "failed"
            scan.error_message = msg
            scan.completed_at  = now

        for scan in db.query(Scan).filter(Scan.extraction_status == "running").all():
            scan.extraction_status = "failed"
            scan.extraction_error  = msg

        for scan in db.query(Scan).filter(Scan.decompile_status == "running").all():
            scan.decompile_status = "failed"
            scan.decompile_error  = msg

        for scan in db.query(Scan).filter(Scan.cve_status == "running").all():
            scan.cve_status = "failed"
            scan.cve_error  = msg

        for scan in db.query(Scan).filter(Scan.disasm_status == "running").all():
            scan.disasm_status = "failed"
            scan.disasm_error  = msg

        db.commit()
        log.info("Startup: orphan recovery complete")
    except Exception:
        log.exception("Startup: orphan recovery failed")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    _bootstrap_db()
    _recover_orphans()
    yield


app = FastAPI(
    title="HELİX-Guard Firmware Security API",
    version="0.4.0",
    description=(
        "Static firmware binary security analysis platform. "
        "Upload a firmware file to receive a detailed risk report."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(scans_router.router)
app.include_router(audit_router.router)
app.include_router(rules_router.router)
app.include_router(firmware_router.router)


@app.get("/health", tags=["meta"], summary="Health check")
def health() -> dict:
    return {"status": "ok", "version": "0.4.0"}
