# Admin Service

# Libraries

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models import Users

# Repositories
from repositories.user_repository import UserRepository

# Core
from core.exceptions import (
    UserNotFoundException,
    InvalidUserRoleException,
    SelfRoleChangeNotAllowedException
)


class AdminService:
    @staticmethod
    def get_all_users(db: Session):
        users = UserRepository.get_all_users(db)
        return users

    @staticmethod
    def lock_user(db: Session, username: str):
        username = username.lower().strip()
        user = UserRepository.get_by_username(db, username)

        if not user:
            raise UserNotFoundException()

        user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
        db.commit()

        return {"message": "User Locked"}

    @staticmethod
    def unlock_user(db: Session, username: str):
        username = username.lower().strip()
        user = UserRepository.get_by_username(db, username)

        if not user:
            raise UserNotFoundException()

        user.failed_attempts = 0
        user.locked_until = None
        db.commit()

        return {"message": "User Unlocked"}

    @staticmethod
    def change_role(db: Session, admin_user: Users, username: str, role: str):
        username = username.lower().strip()
        user = UserRepository.get_by_username(db, username)

        if not user:
            raise UserNotFoundException()

        if role not in ["admin", "user"]:
            raise InvalidUserRoleException()

        if user.username == admin_user.username:
            raise SelfRoleChangeNotAllowedException()

        user.role = role
        db.commit()
        return {"message": "User Role Changed."}