# Email Verification Service

# Libraries
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

# Models
from models.models import EmailVerification

# Repositories
from repositories.email_verification_repository import (
    EmailVerificationRepository,
)

# Services
from services.token_service import TokenService

# Core
from core.security import EMAIL_VERIFICATION_EXPIRE_MINUTES


class EmailVerificationService:

    @staticmethod
    def create_verification_record(db: Session, user_id: int, verification_token: str) -> EmailVerification:

        token_hash = TokenService.hash_token(
            verification_token
        )

        verification_model = EmailVerification(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=EMAIL_VERIFICATION_EXPIRE_MINUTES
                )
            ),
        )

        return EmailVerificationRepository.create(
            db=db,
            verification_model=verification_model,
        )

    @staticmethod
    def get_valid_verification_token(db: Session, verification_token: str) -> EmailVerification | None:

        token_hash = TokenService.hash_token(
            verification_token
        )

        verification_record = (
            EmailVerificationRepository.get_by_token_hash(
                db=db,
                token_hash=token_hash,
            )
        )

        if not verification_record:
            return None

        if verification_record.expires_at < datetime.now(timezone.utc):
            return None

        return verification_record

    @staticmethod
    def delete_user_tokens(db: Session, user_id: int):

        EmailVerificationRepository.delete_user_tokens(
            db=db,
            user_id=user_id,
        )

        db.commit()