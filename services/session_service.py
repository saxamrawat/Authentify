# Session Service

# Libraries

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from models import RefreshToken

# Repositories
from repositories.refresh_token_repository import RefreshTokenRepository

# Core
from core.security import REFRESH_TOKEN_EXPIRE_DAYS

bcrypt_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


class SessionService:

    @staticmethod
    def create_session(db: Session, user_id: int, refresh_token: str):
        hashed_refresh = bcrypt_context.hash(
            refresh_token
        )

        refresh_token_model = RefreshToken(
            user_id=user_id,
            hashed_token=hashed_refresh,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(
                    days=REFRESH_TOKEN_EXPIRE_DAYS
                )
            ),
            is_revoked=False
        )

        db.add(refresh_token_model)
        db.commit()

    @staticmethod
    def get_valid_session(db: Session, user_id: int, refresh_token: str):
        tokens = (
            RefreshTokenRepository
            .get_user_tokens(
                db,
                user_id
            )
        )

        for token in tokens:
            if bcrypt_context.verify(
                refresh_token,
                token.hashed_token
            ):
                return token

        return None

    @staticmethod
    def revoke_session(db: Session, refresh_token: str, user_id: int):
        tokens = (
            RefreshTokenRepository
            .get_user_tokens(
                db,
                user_id
            )
        )

        for token in tokens:
            if bcrypt_context.verify(
                refresh_token,
                token.hashed_token
            ):
                token.is_revoked = True
                db.commit()
                return

    @staticmethod
    def revoke_all_sessions(db: Session, user_id: int):
        RefreshTokenRepository.revoke_all_tokens(
            db,
            user_id
        )

        db.commit()