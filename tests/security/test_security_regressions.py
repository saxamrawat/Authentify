from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.exceptions import (
    RateLimiterUnavailableException,
    SessionSecurityViolationException,
    TooManyLoginAttemptsException,
)
from models.models import RefreshToken
from schemas.auth import RefreshRequest
from services.auth_service import AuthService
from services.refresh_token_service import RefreshTokenService
from services.session_service import SessionService
from services.token_service import TokenService

from tests.auth.test_sessions import (
    create_test_refresh_token,
    create_test_session,
    create_test_user,
)


def create_fake_revocation_store():
    """Create a revocation-store double for regression tests."""

    return SimpleNamespace(
        revoke_session=AsyncMock()
    )


@pytest.mark.asyncio
async def test_rate_limiter_failure_still_fails_closed(monkeypatch):
    """
    Verify a Redis/rate-limiter failure cannot silently bypass login protection.
    """

    user_lookup = MagicMock()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        user_lookup,
    )

    rate_limiter = AsyncMock()
    from services.rate_limiter import RateLimiterError

    rate_limiter.is_allowed.side_effect = RateLimiterError(
        "Redis unavailable"
    )

    with pytest.raises(RateLimiterUnavailableException):
        await AuthService.login(
            db=MagicMock(),
            form_data=SimpleNamespace(
                username="testuser",
                password="StrongPassword1!",
            ),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    user_lookup.assert_not_called()


@pytest.mark.asyncio
async def test_rate_limited_login_does_not_reach_authentication_logic(
    monkeypatch,
):
    """
    Verify a rejected rate-limit request cannot continue into credential
    verification or account-state processing.
    """

    user_lookup = MagicMock()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        user_lookup,
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = False

    with pytest.raises(TooManyLoginAttemptsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=SimpleNamespace(
                username="testuser",
                password="WrongPassword1!",
            ),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    user_lookup.assert_not_called()


@pytest.mark.asyncio
async def test_refresh_token_reuse_invalidates_the_entire_session_set(
    db_session,
    redis_client,
):
    """
    Verify reuse of a previously rotated refresh token triggers compromise
    handling rather than allowing another credential rotation.
    """

    user = create_test_user(
        db_session,
        "regression_refresh_reuse",
    )

    old_token, old_record = _create_real_refresh_token(
        db_session,
        user.id,
    )

    first_session = create_test_session(
        db_session,
        user.id,
        old_record.id,
    )

    second_token, second_record = _create_real_refresh_token(
        db_session,
        user.id,
    )

    second_session = create_test_session(
        db_session,
        user.id,
        second_record.id,
    )

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(redis_client)

    await AuthService.refresh_access_token(
        db=db_session,
        refresh_request=RefreshRequest(
            refresh_token=old_token,
        ),
        revocation_store=revocation_store,
    )

    with pytest.raises(SessionSecurityViolationException):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=old_token,
            ),
            revocation_store=revocation_store,
        )

    db_session.refresh(first_session)
    db_session.refresh(second_session)

    assert first_session.is_active is False
    assert second_session.is_active is False


@pytest.mark.asyncio
async def test_failed_refresh_rotation_leaves_original_credentials_valid(
    db_session,
    monkeypatch,
):
    """
    Verify a failure during refresh-token rotation rolls back the transaction
    so the original refresh token remains usable rather than being consumed.
    """

    user = create_test_user(
        db_session,
        "regression_refresh_rollback",
    )

    old_token, old_record = _create_real_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        old_record.id,
    )

    def fail_rotation(*args, **kwargs):
        raise RuntimeError("forced regression failure")

    monkeypatch.setattr(
        SessionService,
        "update_refresh_token_in_transaction",
        fail_rotation,
    )

    revocation_store = create_fake_revocation_store()

    with pytest.raises(RuntimeError):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=old_token,
            ),
            revocation_store=revocation_store,
        )

    db_session.expire_all()

    refreshed_token = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.id == old_record.id)
        .one()
    )

    refreshed_session = (
        db_session.query(type(session))
        .filter(type(session).id == session.id)
        .one()
    )

    assert refreshed_token.is_revoked is False
    assert refreshed_session.refresh_token_id == old_record.id


@pytest.mark.asyncio
async def test_revoked_session_access_token_cannot_be_reused(
    client,
    db_session,
):
    """
    Verify revoking a session immediately invalidates access tokens associated
    with that session.
    """

    user = create_test_user(
        db_session,
        "regression_session_revoke",
    )

    refresh_token = create_test_refresh_token(
        db_session,
        user.id,
    )

    session = create_test_session(
        db_session,
        user.id,
        refresh_token.id,
    )

    access_token = TokenService.create_access_token(
        username=user.username,
        user_id=user.id,
        role=user.role,
        session_id=str(session.id),
        expire_delta=timedelta(minutes=20),
    )

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    response = client.delete(
        f"/sessions/{session.id}",
        headers=headers,
    )

    assert response.status_code == 200

    response = client.get(
        "/auth/me",
        headers=headers,
    )

    assert response.status_code == 401


def test_invalid_credentials_do_not_expose_authentication_state(client):
    """
    Verify failed authentication uses a generic credential error instead of
    exposing whether the supplied account exists.
    """

    response = client.post(
        "/auth/login",
        data={
            "username": "definitely-nonexistent-user",
            "password": "WrongPassword1!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."


def _create_real_refresh_token(db, user_id):
    """Create a real refresh JWT and persist its hashed database record."""

    refresh_token = TokenService.create_refresh_token(
        user_id=user_id,
        expire_delta=timedelta(days=2),
    )

    record = RefreshTokenService.create_refresh_token_record(
        db=db,
        user_id=user_id,
        refresh_token=refresh_token,
    )

    db.commit()

    return refresh_token, record