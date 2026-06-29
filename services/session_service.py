from uuid import UUID

from sqlalchemy.orm import Session

from models.models import UserSession
from repositories.session_repository import SessionRepository

from core.exceptions import (
    SessionNotFoundException,
    SessionAccessDeniedException
)


class SessionService:

    @staticmethod
    def create_session(
        db: Session,
        user_id: int,
        device_name: str | None,
        ip_address: str | None,
        user_agent: str | None,
    ) -> UserSession:

        return SessionRepository.create(
            db=db,
            user_id=user_id,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @staticmethod
    def get_session(
        db: Session,
        session_id: UUID,
    ) -> UserSession | None:

        return SessionRepository.get_by_id(
            db=db,
            session_id=session_id,
        )

    @staticmethod
    def get_active_sessions(
        db: Session,
        user_id: int,
    ) -> list[UserSession]:

        return SessionRepository.get_active_by_user_id(
            db=db,
            user_id=user_id,
        )

    @staticmethod
    def get_user_session(
        db: Session,
        user_id: int,
        session_id: UUID,
    ) -> UserSession | None:

        session = SessionRepository.get_by_id(
            db=db,
            session_id=session_id,
        )

        if not session:
            raise SessionNotFoundException()

        if session.user_id != user_id:
            raise SessionAccessDeniedException()

        return session

    @staticmethod
    def update_last_active(
        db: Session,
        session_id: UUID,
    ) -> UserSession | None:

        session = SessionRepository.get_by_id(
            db=db,
            session_id=session_id,
        )

        if not session:
            raise SessionNotFoundException()

        return SessionRepository.update_last_active(
            db=db,
            session_obj=session,
        )

    @staticmethod
    def revoke_session(
        db: Session,
        user_id: int,
        session_id: UUID,
    ) -> bool:

        session = SessionRepository.get_by_id(
            db=db,
            session_id=session_id,
        )

        if not session:
            raise SessionNotFoundException()

        if session.user_id != user_id:
            raise SessionAccessDeniedException()

        SessionRepository.revoke(
            db=db,
            session_obj=session,
        )

        return True

    @staticmethod
    def revoke_all_sessions(
        db: Session,
        user_id: int,
    ) -> int:

        return SessionRepository.revoke_all_user_sessions(
            db=db,
            user_id=user_id,
        )