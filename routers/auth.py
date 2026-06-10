from fastapi import APIRouter, Depends, Request
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm
from database import SessionLocal

from schemas.auth import (
    CreateUserRequest,
    ResetPasswordRequest,
    RefreshRequest,
    Token,
    LogOutRequest
)

from models import Users

from dependencies.permissions import get_current_user

from services.auth_service import AuthService

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# DB dependency function
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


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
    db: db_dependency
):
    ip = request.client.host

    return AuthService.login(
        db=db,
        form_data=form_data,
        ip=ip
    )


@router.post("/refresh", response_model=Token)
async def refresh_for_refresh_token(
    refresh_request: RefreshRequest,
    db: db_dependency
):
    return AuthService.refresh_access_token(
        db=db,
        refresh_request=refresh_request
    )


@router.post("/logout")
async def logout(
    logout_request: LogOutRequest,
    db: db_dependency
):
    return AuthService.logout(
        db=db,
        logout_request=logout_request
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