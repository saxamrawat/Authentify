# Refresh Token Repository

# Libraries
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models.models import RefreshToken


class RefreshTokenRepository:

    @staticmethod
    def create(db: Session, refresh_token_model: RefreshToken):
        db.add(refresh_token_model)
        return refresh_token_model

    @staticmethod
    def get_user_tokens(db: Session, user_id: int):
        return (
            db.query(RefreshToken)
            .filter(RefreshToken.user_id == user_id)
            .order_by(RefreshToken.id.desc())
            .all()
        )

    @staticmethod
    def get_by_id(db: Session, refresh_token_id: int):
        return (
            db.query(RefreshToken)
            .filter(
                RefreshToken.id == refresh_token_id
            )
            .first()
        )

    @staticmethod
    def get_by_token_hash(db: Session, token_hash: str):
        return (
            db.query(RefreshToken)
            .filter(
                RefreshToken.token_hash == token_hash
            )
            .first()
        )

    @staticmethod
    def get_active_tokens(db: Session, user_id: int):
        return (
            db.query(RefreshToken)
            .filter(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False
            )
            .all()
        )

    @staticmethod
    def revoke_token(db: Session, token: RefreshToken):
        token.is_revoked = True

    @staticmethod
    def revoke_all_tokens(db: Session, user_id: int):
        db.query(RefreshToken)\
            .filter(RefreshToken.user_id == user_id)\
            .update({"is_revoked": True})

    @staticmethod
    def delete_all_tokens(db: Session, user_id: int):
        db.query(RefreshToken)\
            .filter(RefreshToken.user_id == user_id)\
            .delete()

    @staticmethod
    def delete_expired_tokens(db: Session) -> int:
        count = (
            db.query(RefreshToken)
            .filter(
                RefreshToken.expires_at <
                datetime.now(timezone.utc)
            )
            .delete(synchronize_session=False)
        )

        db.commit()

        return count