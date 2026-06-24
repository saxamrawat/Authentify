from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from starlette import status
from sqlalchemy.orm import Session

# Repositories
from repositories.user_repository import UserRepository

# Models
from models import Users


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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
        db.commit()

        return {"message": "User Locked"}

    @staticmethod
    def unlock_user(db: Session, username: str):
        username = username.lower().strip()
        user = UserRepository.get_by_username(db, username)

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        user.failed_attempts = 0
        user.locked_until = None
        db.commit()

        return {"message": "User Unlocked"}

    @staticmethod
    def change_role(db: Session, admin_user: Users, username: str, role: str):
        username = username.lower().strip()
        user = UserRepository.get_by_username(db, username)

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        if role not in ["admin", "user"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong user role provided.")

        if user.username == admin_user.username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Can't Self Demote.")

        user.role = role
        db.commit()
        return {"message": "User Role Changed."}