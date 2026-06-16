"""Authentication and user management endpoints."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import (
    create_access_token,
    get_current_user,
    hash_password,
    is_locked,
    register_failed_login,
    require_admin,
    reset_failed_login,
    validate_password_strength,
    verify_password,
)
from ..database import get_db
from ..models import User
from ..schemas import CreateUserRequest, TokenResponse, UserInfo

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, summary="Obtain a JWT access token")
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.query(User).filter(User.username == form.username).first()

    if user and is_locked(user):
        log_action(
            db, action="login", username=form.username, success=False,
            detail="Account locked", request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account locked due to repeated failed logins. Try again later.",
        )

    if not user or not verify_password(form.password, user.hashed_password):
        if user:
            register_failed_login(db, user)
        log_action(
            db, action="login", username=form.username, success=False,
            detail="Incorrect credentials", request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_action(
            db, action="login", user=user, success=False,
            detail="Account disabled", request=request,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    reset_failed_login(db, user)
    log_action(db, action="login", user=user, success=True, request=request)

    token = create_access_token({"sub": user.id, "role": user.role})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserInfo, summary="Current user profile")
def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post(
    "/users",
    response_model=UserInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (admin only)",
)
def create_user(
    request: Request,
    body: CreateUserRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="role must be one of: admin, analyst, viewer",
        )
    validate_password_strength(body.password)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already taken")

    user = User(
        username=body.username,
        email=body.email,
        role=body.role,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_action(
        db, action="create_user", user=admin, resource_type="user",
        resource_id=user.id, detail=f"role={user.role}", request=request,
    )
    return user


@router.get(
    "/users",
    response_model=list[UserInfo],
    summary="List all users (admin only)",
)
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> list[User]:
    return db.query(User).order_by(User.created_at).all()
