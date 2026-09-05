# Refresh Token Service

# Libraries

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from models.models import RefreshToken

# Repositories
from repositories.refresh_token_repository import RefreshTokenRepository

# Services
from services.token_service import TokenService

# Core
from core.security import REFRESH_TOKEN_EXPIRE_DAYS


class RefreshTokenService:

    @staticmethod
    def create_refresh_token_record(db: Session, user_id: int, refresh_token: str) -> RefreshToken:
        token_hash = TokenService.hash_token(refresh_token)

        refresh_token_model = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=(
                    datetime.now(timezone.utc)
                    + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            ),
            is_revoked=False,
        )

        db.add(refresh_token_model)
        db.flush()

        return refresh_token_model

    @staticmethod
    def get_valid_refresh_token(db: Session, refresh_token: str):
        token_hash = TokenService.hash_token(
            refresh_token
        )

        return RefreshTokenRepository.get_by_token_hash(
            db=db,
            token_hash=token_hash
        )

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

    @staticmethod
    def cleanup_expired_tokens(db: Session) -> int:

        return RefreshTokenRepository.delete_expired_tokens(
            db=db
        )

    @staticmethod
    def consume_refresh_token(db: Session, refresh_token_id: int) -> bool:
        return RefreshTokenRepository.revoke_token_if_active(
            db=db,
            refresh_token_id=refresh_token_id,
        )