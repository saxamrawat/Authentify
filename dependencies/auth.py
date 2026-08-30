# Auth Dependencies

# Libraries

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Annotated
from jose import JWTError, jwt
from uuid import UUID

# Dependencies
from dependencies.database import get_db
from dependencies.redis import get_revocation_store

# Repositories
from repositories.user_repository import UserRepository

# Core
from core.security import(
    SECRET_KEY,
    ALGORITHM
)

from core.exceptions import(
    InvalidTokenException,
    InvalidTokenTypeException,
    InvalidCredentialsException,
    UserNotFoundException,
    UserLockedException,
    SessionInvalidException
)

# Services
from services.session_service import SessionService
from services.revocation import (
    RevocationStore,
    RevocationStoreError,
)

oauth2_bearer = OAuth2PasswordBearer(
    tokenUrl="auth/login"
)

# Current User Dependency
async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], db: Session = Depends(get_db), revocation_store: RevocationStore = Depends(get_revocation_store)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("token_type") != "access":
            raise InvalidTokenTypeException()

        username = payload.get("sub")
        user_id = payload.get("id")
        session_id = payload.get("session_id")
        jti = str(payload.get("jti"))

        if session_id is None or jti is None:
            raise InvalidTokenException()

        if username is None or user_id is None:
            raise InvalidCredentialsException()

        try:
            if await revocation_store.is_jti_revoked(jti):
                raise InvalidTokenException()

            if await revocation_store.is_session_revoked(session_id):
                raise SessionInvalidException()

        except RevocationStoreError:
            raise InvalidCredentialsException()

        session_uuid = UUID(session_id)

        SessionService.validate_active_session(
            db=db,
            session_id=session_uuid
        )

        SessionService.update_last_active(
            db=db,
            session_id=session_uuid
        )

        user = UserRepository.get_by_id(db, user_id)
        if not user:
            raise UserNotFoundException()

        if (
            user.locked_until
            and user.locked_until > datetime.now(timezone.utc)
        ):
            raise UserLockedException()

        return user

    except JWTError:
        raise InvalidCredentialsException()

# Session Dependency
async def get_current_session_id(token: Annotated[str, Depends(oauth2_bearer)]) -> UUID:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        if payload.get("token_type") != "access":
            raise InvalidTokenTypeException

        session_id = payload.get("session_id")

        if not session_id:
            raise SessionInvalidException()

        return UUID(session_id)

    except JWTError:
        raise InvalidCredentialsException()