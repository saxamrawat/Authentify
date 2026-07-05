# Session Service

# Libraries

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from models.models import RefreshToken

# Repositories
from repositories.refresh_token_repository import RefreshTokenRepository

# Core
from core.security import REFRESH_TOKEN_EXPIRE_DAYS

bcrypt_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


class RefreshTokenService:

    @staticmethod
    def create_refresh_token_record(db: Session, user_id: int, refresh_token: str) -> RefreshToken:
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
        db.refresh(refresh_token_model)

        return refresh_token_model

    @staticmethod
    def get_valid_refresh_token(db: Session, user_id: int, refresh_token: str):
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
    def revoke_refresh_token(db: Session, refresh_token_record: RefreshToken):
        refresh_token_record.is_revoked = True
        db.commit()

    @staticmethod
    def revoke_refresh_token_by_id(db: Session, refresh_token_id: int):
        token = (
            RefreshTokenRepository.get_by_id(
                db=db,
                refresh_token_id=refresh_token_id
            )
        )

        if not token:
            return

        RefreshTokenRepository.revoke_token(db=db, token=token)

        db.commit()

    @staticmethod
    def revoke_all_refresh_tokens(db: Session, user_id: int):
        RefreshTokenRepository.revoke_all_tokens(
            db,
            user_id
        )

        db.commit()