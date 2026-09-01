from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.exceptions import (
    InvalidCredentialsException,
    RateLimiterUnavailableException,
    TooManyLoginAttemptsException,
    UserLockedException,
)
from services.auth_service import AuthService, bcrypt_context


def create_user(
    *,
    password="StrongPassword1!",
    verified=True,
    locked_until=None,
    failed_attempts=0,
):
    return SimpleNamespace(
        id=1,
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        hashed_password=bcrypt_context.hash(password),
        is_verified=verified,
        locked_until=locked_until,
        failed_attempts=failed_attempts,
        role="user",
    )


def create_form(password="StrongPassword1!"):
    return SimpleNamespace(
        username="testuser",
        password=password,
    )

# Valid Authentication
@pytest.mark.asyncio
async def test_login_with_valid_credentials_succeeds(monkeypatch):
    user = create_user()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    monkeypatch.setattr(
        "services.auth_service.RefreshTokenService.create_refresh_token_record",
        MagicMock(return_value=SimpleNamespace(id=1)),
    )

    monkeypatch.setattr(
        "services.auth_service.SessionService.create_session",
        MagicMock(return_value=SimpleNamespace(
            id="session-123"
        )),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    result = await AuthService.login(
        db=MagicMock(),
        form_data=create_form(),
        ip_address="127.0.0.1",
        user_agent=None,
        rate_limiter=rate_limiter,
    )

    assert result.token_type == "bearer"
    assert result.access_token
    assert result.refresh_token

    rate_limiter.is_allowed.assert_awaited_once()

# Incorrect Password
@pytest.mark.asyncio
async def test_login_with_incorrect_password_is_rejected(monkeypatch):
    user = create_user()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    db = MagicMock()

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    with pytest.raises(InvalidCredentialsException):
        await AuthService.login(
            db=db,
            form_data=create_form("WrongPassword1!"),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    assert user.failed_attempts == 1
    db.commit.assert_called()

# Unknown User
@pytest.mark.asyncio
async def test_login_unknown_user_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=None),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    with pytest.raises(InvalidCredentialsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

# Unverified User
@pytest.mark.asyncio
async def test_unverified_user_cannot_login(monkeypatch):
    user = create_user(verified=False)

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    with pytest.raises(InvalidCredentialsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )


# Locked User
@pytest.mark.asyncio
async def test_unverified_user_cannot_login(monkeypatch):
    user = create_user(verified=False)

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    with pytest.raises(InvalidCredentialsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

# Rate-limit Rejection
@pytest.mark.asyncio
async def test_unverified_user_cannot_login(monkeypatch):
    user = create_user(verified=False)

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    with pytest.raises(InvalidCredentialsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

# Redis/rate-limit failure
from services.rate_limiter import RateLimiterError


@pytest.mark.asyncio
async def test_login_fails_closed_when_rate_limiter_unavailable():
    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.side_effect = RateLimiterError(
        "Redis unavailable"
    )

    with pytest.raises(RateLimiterUnavailableException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

# Rate Limiting Before User Lookup

@pytest.mark.asyncio
async def test_rate_limit_rejection_skips_user_lookup(monkeypatch):
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
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    user_lookup.assert_not_called()


# Rate Limiting Does Not Increment Account Lockout

@pytest.mark.asyncio
async def test_rate_limit_rejection_does_not_increment_failed_attempts(
    monkeypatch,
):
    user = create_user(failed_attempts=2)

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = False

    with pytest.raises(TooManyLoginAttemptsException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form("WrongPassword1!"),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    assert user.failed_attempts == 2

@pytest.mark.asyncio
async def test_login_rate_limit_uses_hashed_ip_key(monkeypatch):
    user = create_user()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    monkeypatch.setattr(
        "services.auth_service.RefreshTokenService.create_refresh_token_record",
        MagicMock(return_value=SimpleNamespace(id=1)),
    )

    monkeypatch.setattr(
        "services.auth_service.SessionService.create_session",
        MagicMock(return_value=SimpleNamespace(
            id="session-123"
        )),
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.return_value = True

    await AuthService.login(
        db=MagicMock(),
        form_data=create_form(),
        ip_address="127.0.0.1",
        user_agent=None,
        rate_limiter=rate_limiter,
    )

    key = rate_limiter.is_allowed.await_args.kwargs["key"]

    assert key.startswith(
        "auth:ratelimit:login:ip:"
    )

    assert "127.0.0.1" not in key

@pytest.mark.asyncio
async def test_login_fails_closed_without_user_lookup(monkeypatch):
    user_lookup = MagicMock()

    monkeypatch.setattr(
        "services.auth_service.UserRepository.get_by_username",
        user_lookup,
    )

    rate_limiter = AsyncMock()
    rate_limiter.is_allowed.side_effect = RateLimiterError(
        "Redis unavailable"
    )

    with pytest.raises(RateLimiterUnavailableException):
        await AuthService.login(
            db=MagicMock(),
            form_data=create_form(),
            ip_address="127.0.0.1",
            user_agent=None,
            rate_limiter=rate_limiter,
        )

    user_lookup.assert_not_called()

