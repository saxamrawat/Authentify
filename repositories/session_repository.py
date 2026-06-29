from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from models.models import UserSession


class SessionRepository:

    @staticmethod
    def create(db: Session, **session_data) -> UserSession:
        session = UserSession(**session_data)

        db.add(session)
        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def get_by_id(db: Session, session_id: UUID) -> UserSession | None:
        return (
            db.query(UserSession)
            .filter(UserSession.id == session_id)
            .first()
        )

    @staticmethod
    def get_active_by_user_id(db: Session, user_id: int) -> list[UserSession]:
        return (
            db.query(UserSession)
            .filter(
                UserSession.user_id == user_id,
                UserSession.is_active.is_(True)
            )
            .order_by(UserSession.created_at.desc())
            .all()
        )

    @staticmethod
    def get_all_by_user_id(db: Session, user_id: int) -> list[UserSession]:
        return (
            db.query(UserSession)
            .filter(UserSession.user_id == user_id)
            .order_by(UserSession.created_at.desc())
            .all()
        )

    @staticmethod
    def update_last_active(db: Session, session_obj: UserSession) -> UserSession:
        session_obj.last_active = datetime.now(timezone.utc)

        db.commit()
        db.refresh(session_obj)

        return session_obj

    @staticmethod
    def revoke(db: Session, session_obj: UserSession) -> UserSession:
        session_obj.is_active = False
        session_obj.revoked_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(session_obj)

        return session_obj

    @staticmethod
    def revoke_all_user_sessions(db: Session, user_id: int) -> int:
        result = (
            db.query(UserSession)
            .filter(
                UserSession.user_id == user_id,
                UserSession.is_active.is_(True)
            )
            .update(
                {
                    UserSession.is_active: False,
                    UserSession.revoked_at: datetime.now(timezone.utc),
                },
                synchronize_session=False,
            )
        )

        db.commit()

        return result