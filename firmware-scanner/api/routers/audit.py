"""Audit trail endpoint — admin-only visibility into security-relevant actions."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth import require_admin
from ..database import get_db
from ..models import AuditLog, User
from ..schemas import AuditLogListResponse

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get(
    "",
    response_model=AuditLogListResponse,
    summary="List audit log entries (admin only)",
)
def list_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None, description="Filter by action name"),
    username: str | None = Query(None, description="Filter by username"),
    success: bool | None = Query(None, description="Filter by success/failure"),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> AuditLogListResponse:
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if username:
        q = q.filter(AuditLog.username == username)
    if success is not None:
        q = q.filter(AuditLog.success == success)

    total = q.count()
    items = (
        q.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AuditLogListResponse(items=items, total=total, page=page, page_size=page_size)
