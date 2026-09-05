from main import app

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from dependencies.permissions import require_admin
from dependencies.auth import get_current_user

from unittest.mock import MagicMock

from core.exceptions import (
    InvalidUserRoleException,
    SelfRoleChangeNotAllowedException,
)

from services.admin_service import AdminService

@pytest.mark.asyncio
async def test_admin_user_passes_admin_authorization():
    """Verify a user with the admin role passes the admin authorization dependency."""

    admin_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    result = await require_admin(admin_user)

    assert result is admin_user


@pytest.mark.asyncio
async def test_normal_user_is_rejected_by_admin_authorization():
    """Verify a normal user cannot pass the admin authorization dependency."""

    normal_user = SimpleNamespace(
        id=1,
        username="user",
        role="user",
    )

    with pytest.raises(HTTPException) as exc_info:
        await require_admin(normal_user)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Admin access required."

def test_admin_cannot_change_own_role(monkeypatch):
    """Verify an administrator cannot modify their own role."""

    admin_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    target_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    monkeypatch.setattr(
        "services.admin_service.UserRepository.get_by_username",
        MagicMock(return_value=target_user),
    )

    with pytest.raises(SelfRoleChangeNotAllowedException):
        AdminService.change_role(
            db=MagicMock(),
            admin_user=admin_user,
            username="admin",
            role="user",
        )

def test_invalid_role_cannot_be_assigned(monkeypatch):
    """Verify an administrator cannot assign an unsupported role value."""

    admin_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    target_user = SimpleNamespace(
        id=2,
        username="target",
        role="user",
    )

    monkeypatch.setattr(
        "services.admin_service.UserRepository.get_by_username",
        MagicMock(return_value=target_user),
    )

    with pytest.raises(InvalidUserRoleException):
        AdminService.change_role(
            db=MagicMock(),
            admin_user=admin_user,
            username="target",
            role="superadmin",
        )

def test_admin_can_change_another_users_role(monkeypatch):
    """Verify an administrator can change another user's role."""

    admin_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    target_user = SimpleNamespace(
        id=2,
        username="target",
        role="user",
    )

    db = MagicMock()

    monkeypatch.setattr(
        "services.admin_service.UserRepository.get_by_username",
        MagicMock(return_value=target_user),
    )

    result = AdminService.change_role(
        db=db,
        admin_user=admin_user,
        username="target",
        role="admin",
    )

    assert target_user.role == "admin"
    assert result["message"] == "User Role Changed."
    db.commit.assert_called_once()

def test_admin_can_lock_user(monkeypatch):
    """Verify the admin service locks an existing user account."""

    user = SimpleNamespace(
        username="target",
        locked_until=None,
    )

    db = MagicMock()

    monkeypatch.setattr(
        "services.admin_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    result = AdminService.lock_user(
        db=db,
        username="target",
    )

    assert user.locked_until is not None
    assert result["message"] == "User Locked"
    db.commit.assert_called_once()


def test_admin_can_unlock_user(monkeypatch):
    """Verify unlocking clears the user's failed attempts and lock state."""

    user = SimpleNamespace(
        username="target",
        failed_attempts=5,
        locked_until=object(),
    )

    db = MagicMock()

    monkeypatch.setattr(
        "services.admin_service.UserRepository.get_by_username",
        MagicMock(return_value=user),
    )

    result = AdminService.unlock_user(
        db=db,
        username="target",
    )

    assert user.failed_attempts == 0
    assert user.locked_until is None
    assert result["message"] == "User Unlocked"
    db.commit.assert_called_once()

from fastapi.testclient import TestClient

def test_unauthenticated_user_cannot_access_admin_endpoint(client):
    """Verify an unauthenticated request cannot access an admin endpoint."""

    response = client.get(
        "/admin/users"
    )

    assert response.status_code == 401


def test_normal_user_cannot_access_admin_endpoint(client):
    """Verify an authenticated normal user cannot access an admin endpoint."""

    normal_user = SimpleNamespace(
        id=1,
        username="user",
        role="user",
    )

    async def override_get_current_user():
        return normal_user

    app.dependency_overrides[get_current_user] = (
        override_get_current_user
    )

    try:
        response = client.get(
            "/admin/users"
        )

        assert response.status_code == 403

    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )

def test_admin_user_can_access_admin_endpoint(client):
    """Verify an authenticated administrator can access an admin endpoint."""

    admin_user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    async def override_get_current_user():
        return admin_user

    app.dependency_overrides[get_current_user] = (
        override_get_current_user
    )

    try:
        response = client.get(
            "/admin/users"
        )

        assert response.status_code == 200

    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )
