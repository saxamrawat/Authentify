from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from models.models import RefreshToken, Users
from services.session_service import SessionService
from core.exceptions import (
    SessionAccessDeniedException,
    SessionNotFoundException,
    SessionInvalidException,
)


def create_test_user(db, username):
    """Create a verified test user for session security tests."""

    user = Users(
        username=username,
        email=f"{username}@example.com",
        first_name="Test",
        last_name="User",
        hashed_password="test-hash",
        is_verified=True,
        role="user",
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def create_test_refresh_token(db, user_id):
    """Create a refresh-token record required by the session relationship."""

    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=f"{uuid4().hex}{uuid4().hex}",
        expires_at=datetime.now(timezone.utc),
        is_revoked=False,
    )

    db.add(refresh_token)
    db.commit()
    db.refresh(refresh_token)

    return refresh_token


def create_test_session(db, user_id, refresh_token_id):
    """Create an active session associated with a test user and refresh token."""

    return SessionService.create_session(
        db=db,
        user_id=user_id,
        refresh_token_id=refresh_token_id,
        device_name="pytest",
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


def test_session_belongs_to_user(db_session):
    """Verify a newly created session is associated with the correct user."""

    user = create_test_user(db_session, "sessionuser")
    refresh_token = create_test_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        refresh_token.id,
    )

    assert session.user_id == user.id
    assert session.refresh_token_id == refresh_token.id
    assert session.is_active is True


def test_get_user_session_returns_owned_session(db_session):
    """Verify a user can retrieve a session that belongs to them."""

    user = create_test_user(db_session, "owner")
    refresh_token = create_test_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        refresh_token.id,
    )

    result = SessionService.get_user_session(
        db=db_session,
        user_id=user.id,
        session_id=session.id,
    )

    assert result.id == session.id


def test_user_cannot_access_another_users_session(db_session):
    """Verify one user cannot access another user's session."""

    user_one = create_test_user(db_session, "userone")
    user_two = create_test_user(db_session, "usertwo")

    refresh_token = create_test_refresh_token(
        db_session,
        user_one.id,
    )

    session = create_test_session(
        db_session,
        user_one.id,
        refresh_token.id,
    )

    with pytest.raises(SessionAccessDeniedException):
        SessionService.get_user_session(
            db=db_session,
            user_id=user_two.id,
            session_id=session.id,
        )


def test_get_user_session_rejects_unknown_session(db_session):
    """Verify requesting a nonexistent session raises a not-found error."""

    user = create_test_user(db_session, "missing")

    with pytest.raises(SessionNotFoundException):
        SessionService.get_user_session(
            db=db_session,
            user_id=user.id,
            session_id=uuid4(),
        )


def test_validate_active_session_accepts_active_session(db_session):
    """Verify an existing active session passes session validation."""

    user = create_test_user(db_session, "active")
    refresh_token = create_test_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        refresh_token.id,
    )

    result = SessionService.validate_active_session(
        db=db_session,
        session_id=session.id,
    )

    assert result.id == session.id
    assert result.is_active is True


def test_validate_active_session_rejects_revoked_session(db_session):
    """Verify a revoked session cannot pass active-session validation."""

    user = create_test_user(db_session, "revoked")
    refresh_token = create_test_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        refresh_token.id,
    )

    session.is_active = False
    db_session.commit()

    with pytest.raises(SessionInvalidException):
        SessionService.validate_active_session(
            db=db_session,
            session_id=session.id,
        )


def test_validate_active_session_rejects_unknown_session(db_session):
    """Verify a nonexistent session cannot pass active-session validation."""

    with pytest.raises(SessionInvalidException):
        SessionService.validate_active_session(
            db=db_session,
            session_id=uuid4(),
        )