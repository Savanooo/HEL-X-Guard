"""Audit trail helper — records security-relevant actions for Faz 9 hardening.

Every call is best-effort: a failure to write an audit row must never break
the request it is auditing, so all exceptions are swallowed after rollback.
"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def log_action(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    success: bool = True,
    detail: str | None = None,
    request: Request | None = None,
) -> None:
    """Insert one audit row. Never raises — logging must not break the caller."""
    try:
        entry = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            detail=detail,
            ip_address=_client_ip(request),
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
