"""Pydantic request / response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


# ── Auth ──────────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"


# ── Scans ─────────────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    id: str
    filename: str
    file_size: int | None
    sha256: str | None
    status: str
    risk_score: float | None
    risk_level: str | None
    extraction_status: str | None = None
    decompile_status: str | None = None
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    """Adds the full report, extraction/decompile results, and error messages."""
    report: dict[str, Any] | None = None
    error_message: str | None = None
    extraction: dict[str, Any] | None = None
    extraction_error: str | None = None
    decompile: dict[str, Any] | None = None
    decompile_error: str | None = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


# ── Audit ─────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: str
    user_id: str | None
    username: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    success: bool
    detail: str | None
    ip_address: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
