import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError

from models.models import RefreshToken, UserSession, Users
from repositories.refresh_token_repository import RefreshTokenRepository
from services.auth_service import AuthService
from services.refresh_token_service import RefreshTokenService
from services.token_service import TokenService
from services.session_service import SessionService
from schemas.auth import RefreshRequest

from tests.conftest import TestSessionLocal


def create_test_user(db, username="testuser"):
    user = Users(
        username=username,
        email=f"{username}@example.com",
        first_name="Test",
        last_name="User",
        hashed_password="hashed-password",
        is_verified=True,
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_test_refresh_token(db, user_id, token_hash="test-token-hash"):
    token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ) + __import__("datetime").timedelta(days=7),
        is_revoked=False,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def create_test_session(db, user_id, refresh_token_id):
    session = UserSession(
        user_id=user_id,
        refresh_token_id=refresh_token_id,
        device_name="Test Device",
        ip_address="127.0.0.1",
        user_agent="test-agent",
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def test_duplicate_username_is_rejected_by_database(db_session):
    """Verify PostgreSQL prevents two users from having the same username."""

    create_test_user(db_session, username="duplicate-user")

    duplicate = Users(
        username="duplicate-user",
        email="different@example.com",
        first_name="Another",
        last_name="User",
        hashed_password="hashed-password",
        is_verified=True,
        role="user",
    )

    db_session.add(duplicate)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_duplicate_email_is_rejected_by_database(db_session):
    """Verify PostgreSQL prevents two users from having the same email."""

    create_test_user(db_session, username="first-user")

    duplicate = Users(
        username="second-user",
        email="first-user@example.com",
        first_name="Another",
        last_name="User",
        hashed_password="hashed-password",
        is_verified=True,
        role="user",
    )

    db_session.add(duplicate)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_duplicate_refresh_token_hash_is_rejected_by_database(db_session):
    """Verify PostgreSQL prevents duplicate persistent refresh-token hashes."""

    user = create_test_user(db_session)

    create_test_refresh_token(
        db_session,
        user.id,
        token_hash="duplicate-hash",
    )

    duplicate = RefreshToken(
        user_id=user.id,
        token_hash="duplicate-hash",
        expires_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ) + __import__("datetime").timedelta(days=7),
        is_revoked=False,
    )

    db_session.add(duplicate)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_refresh_token_can_belong_to_only_one_session(db_session):
    """Verify the unique refresh_token_id constraint prevents token/session ambiguity."""

    user = create_test_user(db_session)
    token = create_test_refresh_token(db_session, user.id)

    create_test_session(
        db_session,
        user.id,
        token.id,
    )

    duplicate_session = UserSession(
        user_id=user.id,
        refresh_token_id=token.id,
        device_name="Second Device",
        ip_address="127.0.0.1",
        user_agent="test-agent",
        is_active=True,
    )

    db_session.add(duplicate_session)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_concurrent_refresh_token_consumption_allows_only_one_winner(db_session):
    """Verify concurrent attempts to consume one refresh token produce exactly one winner."""

    user = create_test_user(db_session)
    token = create_test_refresh_token(db_session, user.id)

    barrier = threading.Barrier(2)

    def consume():
        db = TestSessionLocal()

        try:
            barrier.wait()

            result = RefreshTokenService.consume_refresh_token(
                db=db,
                refresh_token_id=token.id,
            )

            db.commit()
            return result

        finally:
            db.rollback()
            db.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(consume),
            executor.submit(consume),
        ]

        results = [future.result() for future in futures]

    assert sorted(results) == [False, True]

    db_session.expire_all()

    refreshed_token = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.id == token.id)
        .one()
    )

    assert refreshed_token.is_revoked is True


def test_concurrent_refresh_rotation_allows_only_one_success(
    db_session,
    monkeypatch,
):
    """Verify concurrent use of one refresh token cannot create two successful rotations."""

    user = create_test_user(db_session)
    token = create_test_refresh_token(
        db_session,
        user.id,
        token_hash="placeholder",
    )
    session = create_test_session(
        db_session,
        user.id,
        token.id,
    )

    # The test needs a real JWT refresh token whose hash matches the
    # persistent record. This setup should use the same TokenService
    # helper used by the application.
    from services.token_service import TokenService
    from core.security import REFRESH_TOKEN_EXPIRE_DAYS

    refresh_token = TokenService.create_refresh_token(
        user.id,
        __import__("datetime").timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    token.token_hash = TokenService.hash_token(refresh_token)
    db_session.commit()

    class FakeRevocationStore:
        async def revoke_session(self, session_id, ttl_seconds):
            return None

    barrier = threading.Barrier(2)

    def refresh():
        db = TestSessionLocal()

        async def run():
            try:
                barrier.wait()

                return await AuthService.refresh_access_token(
                    db=db,
                    refresh_request=RefreshRequest(
                        refresh_token=refresh_token,
                    ),
                    revocation_store=FakeRevocationStore(),
                )
            finally:
                db.close()

        return asyncio.run(run())

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(refresh),
            executor.submit(refresh),
        ]

        results = []

        for future in futures:
            try:
                results.append(("success", future.result()))
            except Exception as exc:
                results.append(("error", exc))

    successes = [
        result
        for result in results
        if result[0] == "success"
    ]

    failures = [
        result
        for result in results
        if result[0] == "error"
    ]

    assert len(successes) == 1
    assert len(failures) == 1

    db_session.expire_all()

    refreshed_session = (
        db_session.query(UserSession)
        .filter(UserSession.id == session.id)
        .one()
    )

    active_tokens = (
        db_session.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user.id,
            RefreshToken.is_revoked.is_(False),
        )
        .all()
    )

    assert token.is_revoked is True
    assert refreshed_session.refresh_token_id != token.id
    assert len(active_tokens) == 1
    assert active_tokens[0].id == refreshed_session.refresh_token_id


def test_failed_refresh_rotation_rolls_back(
    db_session,
    monkeypatch,
):
    """Verify a failed refresh rotation does not leave the old token consumed."""

    user = create_test_user(db_session)
    token = create_test_refresh_token(
        db_session,
        user.id,
        token_hash="rollback-token",
    )
    session = create_test_session(
        db_session,
        user.id,
        token.id,
    )

    original_update = SessionService.update_refresh_token_in_transaction

    def fail_after_token_creation(*args, **kwargs):
        raise RuntimeError("forced rotation failure")

    monkeypatch.setattr(
        SessionService,
        "update_refresh_token_in_transaction",
        fail_after_token_creation,
    )

    consumed = RefreshTokenService.consume_refresh_token(
        db=db_session,
        refresh_token_id=token.id,
    )

    assert consumed is True

    with pytest.raises(RuntimeError):
        try:
            RefreshTokenService.create_refresh_token_record(
                db=db_session,
                user_id=user.id,
                refresh_token="replacement-token",
            )

            SessionService.update_refresh_token_in_transaction(
                db=db_session,
                session_obj=session,
                refresh_token_id=999999,
            )
        finally:
            db_session.rollback()

    db_session.expire_all()

    refreshed_token = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.id == token.id)
        .one()
    )

    refreshed_session = (
        db_session.query(UserSession)
        .filter(UserSession.id == session.id)
        .one()
    )

    replacement_hash = TokenService.hash_token("replacement-token")

    replacement = (
        db_session.query(RefreshToken)
        .filter(RefreshToken.token_hash == replacement_hash)
        .first()
    )

    assert refreshed_token.is_revoked is False
    assert refreshed_session.refresh_token_id == token.id
    assert replacement is None


def test_concurrent_session_revocation_is_safe(db_session):
    """Verify concurrent revocation cannot leave a session active."""

    user = create_test_user(db_session)
    token = create_test_refresh_token(db_session, user.id)
    session = create_test_session(db_session, user.id, token.id)

    barrier = threading.Barrier(2)

    def revoke():
        db = TestSessionLocal()

        try:
            session_obj = SessionRepository.get_by_id(
                db=db,
                session_id=session.id,
            )

            barrier.wait()

            SessionRepository.revoke(
                db=db,
                session_obj=session_obj,
            )

            return True

        finally:
            db.rollback()
            db.close()

    from repositories.session_repository import SessionRepository

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(revoke),
            executor.submit(revoke),
        ]

        [future.result() for future in futures]

    db_session.expire_all()

    refreshed_session = (
        db_session.query(UserSession)
        .filter(UserSession.id == session.id)
        .one()
    )

    assert refreshed_session.is_active is False
    assert refreshed_session.revoked_at is not None


def test_concurrent_logout_all_revokes_all_sessions(db_session):
    """Verify concurrent logout-all operations cannot leave user sessions active."""

    user = create_test_user(db_session)

    tokens = [
        create_test_refresh_token(
            db_session,
            user.id,
            token_hash=f"token-{index}",
        )
        for index in range(3)
    ]

    sessions = [
        create_test_session(
            db_session,
            user.id,
            token.id,
        )
        for token in tokens
    ]

    barrier = threading.Barrier(2)

    def revoke_all():
        db = TestSessionLocal()

        try:
            barrier.wait()

            result = SessionRepository.revoke_all_user_sessions(
                db=db,
                user_id=user.id,
            )

            return result

        finally:
            db.rollback()
            db.close()

    from repositories.session_repository import SessionRepository

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(revoke_all),
            executor.submit(revoke_all),
        ]

        results = [future.result() for future in futures]

    assert sum(results) == len(sessions)

    db_session.expire_all()

    refreshed_sessions = (
        db_session.query(UserSession)
        .filter(UserSession.user_id == user.id)
        .all()
    )

    assert len(refreshed_sessions) == 3

    for session in refreshed_sessions:
        assert session.is_active is False
        assert session.revoked_at is not None