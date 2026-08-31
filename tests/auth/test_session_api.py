from datetime import timedelta

import pytest

from core.security import ACCESS_TOKEN_EXPIRE_MINUTES
from services.token_service import TokenService

from tests.auth.test_sessions import (
    create_test_session,
    create_test_refresh_token,
    create_test_user,
)

def create_authenticated_session(
    db,
    user,
):
    """Create a refresh token, session, and access token for an authenticated test user."""

    refresh_token = create_test_refresh_token(
        db,
        user.id,
    )

    session = create_test_session(
        db,
        user.id,
        refresh_token.id,
    )

    access_token = TokenService.create_access_token(
        username=user.username,
        user_id=user.id,
        role=user.role,
        session_id=str(session.id),
        expire_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    )

    return session, access_token


def auth_headers(token):
    """Create an Authorization header for a test access token."""

    return {
        "Authorization": f"Bearer {token}"
    }

def test_authenticated_user_can_get_active_sessions(
    client,
    db_session,
):
    """Verify an authenticated user can retrieve their active sessions."""

    user = create_test_user(
        db_session,
        "session_api_list",
    )

    session, token = create_authenticated_session(
        db_session,
        user,
    )

    response = client.get(
        "/sessions",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["session_id"] == str(session.id)
    assert data[0]["is_active"] is True

def test_active_sessions_identifies_current_session(
    client,
    db_session,
):
    """Verify the session represented by the access token is marked as the current session."""

    user = create_test_user(
        db_session,
        "session_api_current",
    )

    current_session, token = create_authenticated_session(
        db_session,
        user,
    )

    response = client.get(
        "/sessions",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.json()

    current = next(
        item
        for item in data
        if item["session_id"] == str(current_session.id)
    )

    assert current["current"] is True

def test_user_cannot_access_another_users_session_details(
    client,
    db_session,
):
    """Verify an authenticated user cannot retrieve another user's session details."""

    user_one = create_test_user(
        db_session,
        "session_api_owner",
    )

    user_two = create_test_user(
        db_session,
        "session_api_attacker",
    )

    session, _ = create_authenticated_session(
        db_session,
        user_one,
    )

    _, attacker_token = create_authenticated_session(
        db_session,
        user_two,
    )

    response = client.get(
        f"/sessions/{session.id}",
        headers=auth_headers(attacker_token),
    )

    assert response.status_code == 404

@pytest.mark.asyncio
async def test_user_cannot_revoke_another_users_session(
    client,
    db_session,
):
    """Verify an authenticated user cannot revoke another user's session."""

    user_one = create_test_user(
        db_session,
        "revoke_owner",
    )

    user_two = create_test_user(
        db_session,
        "revoke_attacker",
    )

    target_session, _ = create_authenticated_session(
        db_session,
        user_one,
    )

    _, attacker_token = create_authenticated_session(
        db_session,
        user_two,
    )

    response = client.delete(
        f"/sessions/{target_session.id}",
        headers=auth_headers(attacker_token),
    )

    assert response.status_code == 403

    db_session.refresh(target_session)

    assert target_session.is_active is True

@pytest.mark.asyncio
async def test_revoked_session_access_token_is_rejected(
    client,
    db_session,
):
    """Verify an access token belonging to a revoked session can no longer authenticate."""

    user = create_test_user(
        db_session,
        "revoked_access",
    )

    session, token = create_authenticated_session(
        db_session,
        user,
    )

    response = client.delete(
        f"/sessions/{session.id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    response = client.get(
        "/sessions",
        headers=auth_headers(token),
    )

    assert response.status_code == 401

@pytest.mark.asyncio
async def test_logout_all_revokes_all_user_sessions(
    client,
    db_session,
):
    """Verify logout-all deactivates every active session and invalidates the current access token."""

    user = create_test_user(
        db_session,
        "logout_all",
    )

    session_one, token_one = create_authenticated_session(
        db_session,
        user,
    )

    session_two, _ = create_authenticated_session(
        db_session,
        user,
    )

    response = client.post(
        "/sessions/logout-all",
        headers=auth_headers(token_one),
    )

    assert response.status_code == 200

    db_session.refresh(session_one)
    db_session.refresh(session_two)

    assert session_one.is_active is False
    assert session_two.is_active is False

    response = client.get(
        "/sessions",
        headers=auth_headers(token_one),
    )

    assert response.status_code == 401

def test_session_endpoint_requires_authentication(client):
    """Verify the session endpoint rejects requests without an access token."""

    response = client.get("/sessions")

    assert response.status_code == 401

def test_session_endpoint_rejects_invalid_access_token(client):
    """Verify the session endpoint rejects a malformed or invalid access token."""

    response = client.get(
        "/sessions",
        headers=auth_headers("not-a-valid-jwt"),
    )

    assert response.status_code == 401

