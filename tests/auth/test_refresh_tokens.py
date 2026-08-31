from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from jose import jwt

from core.security import (
    SECRET_KEY,
    ALGORITHM,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from core.exceptions import (
    RefreshTokenNotRecognizedException,
    RefreshTokenExpiredException,
    InvalidTokenTypeException,
    SessionSecurityViolationException,
)
from models.models import RefreshToken
from schemas.auth import RefreshRequest
from services.auth_service import AuthService
from services.refresh_token_service import RefreshTokenService
from services.session_service import SessionService
from services.token_service import TokenService

from tests.auth.test_sessions import (
    create_test_user,
    create_test_refresh_token,
    create_test_session,
)

def create_refresh_token_for_user(db, user_id):
    """Create a real refresh JWT and persist its hashed token record."""

    refresh_token = TokenService.create_refresh_token(
        user_id=user_id,
        expire_delta=timedelta(
            days=REFRESH_TOKEN_EXPIRE_DAYS
        ),
    )

    record = RefreshTokenService.create_refresh_token_record(
        db=db,
        user_id=user_id,
        refresh_token=refresh_token,
    )

    return refresh_token, record

def test_refresh_token_is_persisted_as_hash(db_session):
    """Verify the raw refresh token is never stored in the database."""

    user = create_test_user(
        db_session,
        "refresh_hash",
    )

    raw_token, record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    assert record.token_hash != raw_token
    assert len(record.token_hash) == 64

    stored = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.id == record.id)
        .first()
    )

    assert stored.token_hash == TokenService.hash_token(
        raw_token
    )

def test_valid_refresh_token_is_recognized(db_session):
    """Verify a valid raw refresh token resolves to its persisted token record."""

    user = create_test_user(
        db_session,
        "refresh_valid",
    )

    raw_token, record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    result = RefreshTokenService.get_valid_refresh_token(
        db=db_session,
        refresh_token=raw_token,
    )

    assert result is not None
    assert result.id == record.id
    assert result.user_id == user.id
    assert result.is_revoked is False

def test_unknown_refresh_token_is_not_recognized(db_session):
    """Verify a refresh token that was never persisted cannot be recognized."""

    user = create_test_user(
        db_session,
        "refresh_unknown",
    )

    create_refresh_token_for_user(
        db_session,
        user.id,
    )

    result = RefreshTokenService.get_valid_refresh_token(
        db=db_session,
        refresh_token="not-a-real-refresh-token",
    )

    assert result is None

def test_refresh_token_can_be_revoked(db_session):
    """Verify revoking a refresh token persists its revoked state."""

    user = create_test_user(
        db_session,
        "refresh_revoke",
    )

    _, record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    RefreshTokenService.revoke_refresh_token(
        db=db_session,
        refresh_token_record=record,
    )

    db_session.refresh(record)

    assert record.is_revoked is True

def test_refresh_token_can_be_revoked(db_session):
    """Verify revoking a refresh token persists its revoked state."""

    user = create_test_user(
        db_session,
        "refresh_revoke",
    )

    _, record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    RefreshTokenService.revoke_refresh_token(
        db=db_session,
        refresh_token_record=record,
    )

    db_session.refresh(record)

    assert record.is_revoked is True

@pytest.mark.asyncio
async def test_refresh_token_rotation_revokes_old_token(
    db_session,
    redis_client,
):
    """Verify successful refresh revokes the old token and issues a replacement token."""

    user = create_test_user(
        db_session,
        "refresh_rotation",
    )

    old_token, old_record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    create_test_session(
        db_session,
        user.id,
        old_record.id,
    )

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    result = await AuthService.refresh_access_token(
        db=db_session,
        refresh_request=RefreshRequest(
            refresh_token=old_token
        ),
        revocation_store=revocation_store,
    )

    assert result.access_token
    assert result.refresh_token
    assert result.refresh_token != old_token
    assert result.token_type == "bearer"

    db_session.refresh(old_record)

    assert old_record.is_revoked is True

    new_record = (
        db_session.query(RefreshToken)
        .filter(
            RefreshToken.token_hash
            == TokenService.hash_token(
                result.refresh_token
            )
        )
        .first()
    )

    assert new_record is not None
    assert new_record.is_revoked is False
    assert new_record.user_id == user.id

@pytest.mark.asyncio
async def test_rotated_refresh_token_cannot_be_reused(
    db_session,
    redis_client,
):
    """Verify a refresh token rejected after it has already been rotated."""

    user = create_test_user(
        db_session,
        "refresh_reuse",
    )

    old_token, old_record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    create_test_session(
        db_session,
        user.id,
        old_record.id,
    )

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    await AuthService.refresh_access_token(
        db=db_session,
        refresh_request=RefreshRequest(
            refresh_token=old_token
        ),
        revocation_store=revocation_store,
    )

    with pytest.raises(
        SessionSecurityViolationException
    ):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=old_token
            ),
            revocation_store=revocation_store,
        )

@pytest.mark.asyncio
async def test_refresh_token_reuse_revokes_all_user_sessions(
    db_session,
    redis_client,
):
    """Verify refresh-token reuse triggers revocation of all sessions for the affected user."""

    user = create_test_user(
        db_session,
        "refresh_compromise",
    )

    old_token, old_record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    session_one = create_test_session(
        db_session,
        user.id,
        old_record.id,
    )

    second_token, second_record = create_refresh_token_for_user(
        db_session,
        user.id,
    )

    session_two = create_test_session(
        db_session,
        user.id,
        second_record.id,
    )

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    await AuthService.refresh_access_token(
        db=db_session,
        refresh_request=RefreshRequest(
            refresh_token=old_token
        ),
        revocation_store=revocation_store,
    )

    with pytest.raises(
        SessionSecurityViolationException
    ):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=old_token
            ),
            revocation_store=revocation_store,
        )

    db_session.refresh(session_one)
    db_session.refresh(session_two)

    assert session_one.is_active is False
    assert session_two.is_active is False

    tokens = (
        db_session.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user.id
        )
        .all()
    )

    assert all(
        token.is_revoked
        for token in tokens
    )

@pytest.mark.asyncio
async def test_expired_refresh_token_is_rejected(
    db_session,
    redis_client,
):
    """Verify an expired refresh token cannot be used to obtain new credentials."""

    user = create_test_user(
        db_session,
        "refresh_expired",
    )

    expired_token = TokenService.create_refresh_token(
        user_id=user.id,
        expire_delta=timedelta(seconds=-1),
    )

    record = RefreshToken(
        user_id=user.id,
        token_hash=TokenService.hash_token(
            expired_token
        ),
        expires_at=(
            datetime.now(timezone.utc)
            - timedelta(seconds=1)
        ),
        is_revoked=False,
    )

    db_session.add(record)
    db_session.commit()

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    with pytest.raises(
        RefreshTokenNotRecognizedException
    ):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=expired_token
            ),
            revocation_store=revocation_store,
        )

@pytest.mark.asyncio
async def test_access_token_cannot_be_used_as_refresh_token(
    db_session,
    redis_client,
):
    """Verify an access token cannot be presented to the refresh endpoint."""

    user = create_test_user(
        db_session,
        "wrong_type",
    )

    access_token = TokenService.create_access_token(
        username=user.username,
        user_id=user.id,
        role=user.role,
        session_id=str(uuid4()),
        expire_delta=timedelta(minutes=20),
    )

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    with pytest.raises(InvalidTokenTypeException):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=access_token
            ),
            revocation_store=revocation_store,
        )

@pytest.mark.asyncio
async def test_refresh_token_cannot_be_used_for_another_user(
    db_session,
    redis_client,
):
    """Verify a refresh token cannot be associated with a different user's identity."""

    user_one = create_test_user(
        db_session,
        "refresh_user_one",
    )

    user_two = create_test_user(
        db_session,
        "refresh_user_two",
    )

    token, record = create_refresh_token_for_user(
        db_session,
        user_one.id,
    )

    forged_payload = {
        "sub": str(user_two.id),
        "token_type": "refresh",
        "jti": "forged-jti",
        "exp": (
            datetime.now(timezone.utc)
            + timedelta(days=1)
        ),
    }

    forged_token = jwt.encode(
        forged_payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    # Persist the forged token under user one.
    record.token_hash = TokenService.hash_token(
        forged_token
    )
    db_session.commit()

    from infrastructure.redis.revocation import RedisRevocationStore

    revocation_store = RedisRevocationStore(
        redis_client
    )

    with pytest.raises(
        RefreshTokenNotRecognizedException
    ):
        await AuthService.refresh_access_token(
            db=db_session,
            refresh_request=RefreshRequest(
                refresh_token=forged_token
            ),
            revocation_store=revocation_store,
        )
