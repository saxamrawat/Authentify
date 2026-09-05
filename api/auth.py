# Auth API Routers

# Libraries

from fastapi import APIRouter, Depends, Request
from typing import Annotated
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm
from models.models import Users

# Dependencies
from dependencies.database import db_dependency
from dependencies.auth import get_current_user
from dependencies.redis import get_revocation_store
from dependencies.redis import get_rate_limiter

# Schemas
from schemas.auth import (
    CreateUserRequest,
    ResetPasswordRequest,
    RefreshRequest,
    Token,
    LogOutRequest
)

# Services
from services.auth_service import AuthService
from services.revocation import RevocationStore
from services.rate_limiter import RateLimiter


router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(
    create_user_request: CreateUserRequest,
    db: db_dependency
):
    return AuthService.register_user(
        db=db,
        create_user_request=create_user_request
    )


@router.post("/login", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
):
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent")

    return await AuthService.login(
        db=db,
        form_data=form_data,
        ip_address=ip_address,
        user_agent=user_agent,
        rate_limiter=rate_limiter,
    )


@router.post("/refresh", response_model=Token)
async def refresh_for_refresh_token(
    refresh_request: RefreshRequest,
    db: db_dependency,
    revocation_store: RevocationStore = Depends(get_revocation_store)
):
    return await AuthService.refresh_access_token(
        db=db,
        refresh_request=refresh_request,
        revocation_store=revocation_store
    )


@router.post("/logout")
async def logout(
    logout_request: LogOutRequest,
    db: db_dependency,
    revocation_store: RevocationStore = Depends(get_revocation_store)
):
    return await AuthService.logout(
        db=db,
        logout_request=logout_request,
        revocation_store=revocation_store
    )


@router.get("/verify-email")
async def verify_email(
    token: str,
    db: db_dependency
):
    return AuthService.verify_email(
        db=db,
        token=token
    )


@router.post("/request-password-reset")
async def request_password_reset(
    email: str,
    db: db_dependency
):
    return AuthService.request_password_reset(
        db=db,
        email=email
    )


@router.post("/reset-password")
async def reset_password(
    reset_request: ResetPasswordRequest,
    db: db_dependency
):
    return AuthService.reset_password(
        db=db,
        reset_request=reset_request
    )


@router.get("/me")
async def get_me(
    current_user: Annotated[Users, Depends(get_current_user)]
):
    return AuthService.get_me(
        current_user=current_user
    )