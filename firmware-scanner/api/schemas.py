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


class DecompileRequest(BaseModel):
    processor: str | None = None
    base_address: str | None = None


class DisasmRequest(BaseModel):
    arch: str = "thumb"  # thumb | arm | arm64 | x86 | x86_64


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
    # Tier 2 opt-in results
    cve_status: str | None = None
    cve: dict[str, Any] | None = None
    cve_error: str | None = None
    disasm_status: str | None = None
    disasm: dict[str, Any] | None = None
    disasm_error: str | None = None
    # Rootfs deep analysis (Feature 5) — stored inside extraction_json["rootfs"]
    rootfs: dict[str, Any] | None = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


# ── Diff ──────────────────────────────────────────────────────────────────────

class DiffScanMeta(BaseModel):
    id: str
    filename: str
    risk_score: float | None
    risk_level: str | None
    created_at: datetime
    entropy: float | None
    file_size: int | None
    suspicious_count: int
    yara_count: int


class DiffSummary(BaseModel):
    risk_delta: float
    entropy_delta: float
    file_size_delta: int | None
    strings_added: int
    strings_removed: int
    yara_new: int
    yara_resolved: int


class ScanDiffResponse(BaseModel):
    scan_a: DiffScanMeta
    scan_b: DiffScanMeta
    summary: DiffSummary
    strings_added: list[dict[str, Any]]
    strings_removed: list[dict[str, Any]]
    yara_new: list[dict[str, Any]]
    yara_resolved: list[dict[str, Any]]


# ── YARA rules ────────────────────────────────────────────────────────────────

class YaraRuleResponse(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    content: str
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class YaraRuleCreate(BaseModel):
    name: str
    description: str = ""
    severity: str = "medium"  # low|medium|high|critical
    content: str
    enabled: bool = True


class YaraRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    content: str | None = None
    enabled: bool | None = None


class YaraValidateRequest(BaseModel):
    content: str


class YaraValidateResponse(BaseModel):
    ok: bool
    error: str | None = None


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
