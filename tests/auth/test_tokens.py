import pytest
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from core.security import SECRET_KEY, ALGORITHM
from services.token_service import TokenService

# Unit Test for Tokens

def test_access_token_contains_required_claims():
    """Verify an access token contains all required authentication claims."""

    session_id = "123e4567-e89b-12d3-a456-426614174000"

    token = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id=session_id,
        expire_delta=timedelta(minutes=20),
    )

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload["sub"] == "testuser"
    assert payload["id"] == 42
    assert payload["role"] == "user"
    assert payload["session_id"] == session_id
    assert payload["token_type"] == "access"

    assert "jti" in payload
    assert payload["jti"]

    assert "iat" in payload
    assert "exp" in payload


def test_access_token_has_unique_jti():
    """Verify each newly created access token receives a unique JTI."""

    token_one = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id="session-1",
        expire_delta=timedelta(minutes=20),
    )

    token_two = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id="session-1",
        expire_delta=timedelta(minutes=20),
    )

    payload_one = jwt.decode(
        token_one,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    payload_two = jwt.decode(
        token_two,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload_one["jti"] != payload_two["jti"]


def test_access_token_expiration_is_correct():
    """Verify an access token's issued-at and expiration timestamps use the requested lifetime."""

    before = datetime.now(timezone.utc).replace(microsecond=0)

    token = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id="session-1",
        expire_delta=timedelta(minutes=20),
    )

    after = datetime.now(timezone.utc).replace(microsecond=0)

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    issued_at = datetime.fromtimestamp(
        payload["iat"],
        tz=timezone.utc,
    )

    expires_at = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )

    assert before <= issued_at <= after
    assert expires_at - issued_at == timedelta(minutes=20)


def test_refresh_token_contains_required_claims():
    """Verify a refresh token contains the required refresh-token claims."""

    token = TokenService.create_refresh_token(
        user_id=42,
        expire_delta=timedelta(days=2),
    )

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload["sub"] == "42"
    assert payload["token_type"] == "refresh"

    assert "jti" in payload
    assert payload["jti"]

    assert "exp" in payload


def test_refresh_tokens_have_unique_jti():
    """Verify each newly created refresh token receives a unique JTI."""

    token_one = TokenService.create_refresh_token(
        user_id=42,
        expire_delta=timedelta(days=2),
    )

    token_two = TokenService.create_refresh_token(
        user_id=42,
        expire_delta=timedelta(days=2),
    )

    payload_one = jwt.decode(
        token_one,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    payload_two = jwt.decode(
        token_two,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload_one["jti"] != payload_two["jti"]


def test_refresh_token_hash_is_sha256():
    """Verify refresh tokens are deterministically hashed using SHA-256."""

    import hashlib

    token = "test-refresh-token"

    hashed = TokenService.hash_token(token)

    expected = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    assert hashed == expected
    assert len(hashed) == 64

def test_email_verification_token_contains_required_claims():
    """Verify an email-verification token contains the required verification claims."""

    token = TokenService.create_email_verification_token(
        user_id=42,
        expire_delta=timedelta(minutes=15),
    )

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload["sub"] == "42"
    assert payload["token_type"] == "email_verification"
    assert "exp" in payload


def test_password_reset_token_contains_required_claims():
    """Verify a password-reset token contains the required password-reset claims."""

    token = TokenService.create_password_reset_token(
        user_id=42,
        expire_delta=timedelta(minutes=15),
    )

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )

    assert payload["sub"] == "42"
    assert payload["token_type"] == "password_reset"
    assert "exp" in payload

# Cryptographic Rejection Tests

def test_tampered_access_token_is_rejected():
    """Verify modifying an access token's payload invalidates its signature."""

    token = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id="session-1",
        expire_delta=timedelta(minutes=20),
    )

    header, payload, signature = token.split(".")

    tampered_payload = payload[:-1] + (
        "A" if payload[-1] != "A" else "B"
    )

    tampered_token = ".".join(
        [header, tampered_payload, signature]
    )

    with pytest.raises(JWTError):
        jwt.decode(
            tampered_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )


def test_expired_access_token_is_rejected():
    """Verify an expired access token cannot be decoded as a valid JWT."""

    token = TokenService.create_access_token(
        username="testuser",
        user_id=42,
        role="user",
        session_id="session-1",
        expire_delta=timedelta(seconds=-1),
    )

    with pytest.raises(JWTError):
        jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )