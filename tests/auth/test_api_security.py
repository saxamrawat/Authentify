import pytest
from core.device import get_device_name
from types import SimpleNamespace

def test_protected_me_endpoint_requires_authentication(client):
    """Verify the /auth/me endpoint rejects requests without authentication."""

    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_refresh_endpoint_rejects_missing_request_body(client):
    """Verify the refresh endpoint rejects a request without the required body."""

    response = client.post("/auth/refresh")

    assert response.status_code == 422


def test_refresh_endpoint_rejects_malformed_request_body(client):
    """Verify the refresh endpoint rejects a body that does not contain a refresh token."""

    response = client.post(
        "/auth/refresh",
        json={"token": "not-a-refresh-token"},
    )

    assert response.status_code == 422


def test_login_rejects_missing_credentials(client):
    """Verify the login endpoint rejects requests missing required form credentials."""

    response = client.post(
        "/auth/login",
        data={},
    )

    assert response.status_code == 422


def test_login_rejects_malformed_request_content(client):
    """Verify the login endpoint does not accept JSON in place of OAuth2 form data."""

    response = client.post(
        "/auth/login",
        json={
            "username": "testuser",
            "password": "StrongPassword1!",
        },
    )

    assert response.status_code == 422

def test_session_details_rejects_invalid_uuid_for_authenticated_user(
    client,
    db_session,
):
    """Verify an authenticated request with an invalid session UUID is rejected by API validation."""

    from tests.auth.test_session_api import (
        create_authenticated_session,
        auth_headers,
    )
    from tests.auth.test_sessions import create_test_user

    user = create_test_user(
        db_session,
        "api_invalid_uuid",
    )

    _, token = create_authenticated_session(
        db_session,
        user,
    )

    response = client.get(
        "/sessions/not-a-valid-uuid",
        headers=auth_headers(token),
    )

    assert response.status_code == 422


def test_admin_endpoint_does_not_expose_database_error_details(
    client,
):
    """Verify an unauthenticated admin request returns an authentication error instead of internal details."""

    response = client.get("/admin/users")

    assert response.status_code == 401

    body = response.text.lower()

    assert "traceback" not in body
    assert "sqlalchemy" not in body
    assert "database" not in body


def test_invalid_access_token_does_not_expose_token_details(
    client,
):
    """Verify an invalid access token produces a generic authentication response without token internals."""

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401

    body = response.text.lower()

    assert "traceback" not in body
    assert "secret" not in body
    assert "signature" not in body

def test_login_does_not_reveal_whether_username_exists(client):
    """Verify failed login responses do not reveal whether the supplied username exists."""

    existing_user_response = client.post(
        "/auth/login",
        data={
            "username": "definitely-not-a-real-user",
            "password": "WrongPassword1!",
        },
    )

    assert existing_user_response.status_code == 401

    response_body = existing_user_response.json()

    assert response_body["detail"] == "Invalid credentials."

def test_unknown_user_agent_returns_unknown_device():
    """Verify an unrecognized User-Agent does not cause an exception and returns a safe fallback."""

    result = get_device_name(
        "pytest"
    )

    assert result == "Unknown Device"

def test_unrecognized_user_agent_returns_unknown_device(monkeypatch):
    """Verify a User-Agent that cannot be parsed does not cause an exception."""

    parsed = SimpleNamespace(
        user_agent=None,
        os=None,
        device=None,
    )

    monkeypatch.setattr(
        "core.device.parse",
        lambda _: parsed,
    )

    result = get_device_name("unrecognized-user-agent")

    assert result == "Unknown Device"

