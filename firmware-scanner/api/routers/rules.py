"""YARA rule management — CRUD + compile-time validation.

Rules are stored in the database and merged with the built-in firmware_rules.yar
at scan start so newly created rules take effect on the next scan without a
server restart.  All write operations validate the YARA source first; invalid
rules are rejected before they can be persisted.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import require_admin, require_analyst, require_viewer
from ..database import get_db
from ..models import User, YaraRule
from ..schemas import (
    YaraRuleCreate,
    YaraRuleResponse,
    YaraRuleUpdate,
    YaraValidateRequest,
    YaraValidateResponse,
)

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


# ── Validate helper ───────────────────────────────────────────────────────────

def _compile_or_raise(content: str) -> None:
    """Compile YARA source; raise HTTP 422 if it fails."""
    try:
        import yara
        yara.compile(source=content)
    except ImportError:
        pass  # yara-python absent — validate at scan time
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"YARA compile error: {exc}",
        )


# ── Read ──────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[YaraRuleResponse], summary="List all YARA rules")
def list_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> list[YaraRule]:
    return db.query(YaraRule).order_by(YaraRule.created_at.desc()).all()


@router.get("/{rule_id}", response_model=YaraRuleResponse, summary="Get a single YARA rule")
def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> YaraRule:
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


# ── Validate (no save) ────────────────────────────────────────────────────────

@router.post(
    "/validate",
    response_model=YaraValidateResponse,
    summary="Compile-check a YARA rule without saving it",
)
def validate_rule(
    body: YaraValidateRequest,
    current_user: User = Depends(require_analyst),
) -> dict:
    """Try to compile *body.content* with yara.compile(); return {ok, error}.

    Nothing is persisted — this endpoint exists to give the UI inline feedback
    before the user saves, preventing the broken-rule-breaks-all-scans bug.
    """
    try:
        import yara
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="yara-python is not installed on this server",
        )

    try:
        yara.compile(source=body.content)
        return {"ok": True, "error": None}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ── Create ────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=YaraRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new YARA rule (validates before saving)",
)
def create_rule(
    body: YaraRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> YaraRule:
    _compile_or_raise(body.content)

    if db.query(YaraRule).filter(YaraRule.name == body.name).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A rule named '{body.name}' already exists",
        )

    rule = YaraRule(
        name=body.name,
        description=body.description,
        severity=body.severity,
        content=body.content,
        enabled=body.enabled,
        created_by=current_user.username,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    log_action(
        db, action="create_yara_rule", user=current_user,
        resource_type="yara_rule", resource_id=rule.id,
        detail=rule.name, request=request,
    )
    return rule


# ── Update ────────────────────────────────────────────────────────────────────

@router.put(
    "/{rule_id}",
    response_model=YaraRuleResponse,
    summary="Update a YARA rule (validates content before saving)",
)
def update_rule(
    rule_id: str,
    body: YaraRuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> YaraRule:
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    if body.content is not None:
        _compile_or_raise(body.content)
        rule.content = body.content
    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.severity is not None:
        rule.severity = body.severity
    if body.enabled is not None:
        rule.enabled = body.enabled

    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rule)

    log_action(
        db, action="update_yara_rule", user=current_user,
        resource_type="yara_rule", resource_id=rule.id,
        detail=rule.name, request=request,
    )
    return rule


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a YARA rule (admin only)",
)
def delete_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    rule_name = rule.name
    db.delete(rule)
    db.commit()

    log_action(
        db, action="delete_yara_rule", user=current_user,
        resource_type="yara_rule", resource_id=rule_id,
        detail=rule_name, request=request,
    )
