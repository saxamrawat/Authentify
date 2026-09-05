from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from models.models import PasswordReset

from repositories.password_reset_repository import (
    PasswordResetRepository,
)

from services.token_service import TokenService

from core.security import PASSWORD_RESET_EXPIRE_MINUTES


class PasswordResetService:

    @staticmethod
    def create_reset_record(db: Session, user_id: int, reset_token: str) -> PasswordReset:

        token_hash = TokenService.hash_token(
            reset_token
        )

        password_reset_model = PasswordReset(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=PASSWORD_RESET_EXPIRE_MINUTES
                )
            ),
        )

        return PasswordResetRepository.create(
            db=db,
            password_reset_model=password_reset_model,
        )

    @staticmethod
    def get_valid_reset_token(db: Session, reset_token: str) -> PasswordReset | None:

        token_hash = TokenService.hash_token(
            reset_token
        )

        reset_record = (
            PasswordResetRepository.get_by_token_hash(
                db=db,
                token_hash=token_hash,
            )
        )

        if not reset_record:
            return None

        if reset_record.expires_at < datetime.now(timezone.utc):
            return None

        return reset_record

    @staticmethod
    def delete_user_tokens(db: Session, user_id: int):

        PasswordResetRepository.delete_user_tokens(
            db=db,
            user_id=user_id,
        )

        db.commit()