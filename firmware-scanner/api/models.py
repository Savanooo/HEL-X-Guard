"""SQLAlchemy ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(256), unique=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin|analyst|viewer
    hashed_password: Mapped[str] = mapped_column(String(256))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # Brute-force lockout state
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="user")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(256))
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Host path of the saved upload — needed to re-trigger extract/decompile later
    stored_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # pending → running → completed | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)

    report_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Faz 2 deep analysis — binwalk extraction, triggered on demand
    extraction_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    extraction_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    extraction_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional/heavy — Ghidra headless decompilation, triggered on demand
    decompile_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decompile_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    decompile_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tier 2 opt-in — CVE cross-reference (triggered via POST /scans/{id}/analyze/cve)
    cve_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cve_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tier 2 opt-in — instruction histogram (triggered via POST /scans/{id}/analyze/disasm)
    disasm_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    disasm_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    disasm_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship("User", back_populates="scans")


class YaraRule(Base):
    """User-managed YARA rules stored in the database.

    Rules are validated at write time (must compile) and merged with the
    built-in firmware_rules.yar at scan start.  Only enabled rules are used.
    """
    __tablename__ = "yara_rules"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # low|medium|high|critical
    content: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
