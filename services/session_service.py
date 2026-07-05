# Session Service

# Libraries
from uuid import UUID
from sqlalchemy.orm import Session

# Models
from models.models import UserSession

# Schemas
from schemas.session_schema import SessionResponse
from schemas.session_schema import MessageResponse
from schemas.session_schema import SessionDetailsResponse

# Repositories
from repositories.session_repository import SessionRepository

# Core
from core.exceptions import (
    SessionNotFoundException,
    SessionAccessDeniedException
)

# Services
from services.refresh_token_service import RefreshTokenService


class SessionService:

    @staticmethod
    def create_session(db: Session, user_id: int, refresh_token_id : int, device_name: str | None, ip_address: str | None, user_agent: str | None) -> UserSession:

        return SessionRepository.create(
            db=db,
            user_id=user_id,
            refresh_token_id=refresh_token_id,
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
    def get_session_details(db: Session, user_id: int, session_id: UUID) -> SessionDetailsResponse:

        session = SessionRepository.get_by_id(
            db=db,
            session_id=session_id
        )

        if not session:
            raise SessionNotFoundException()

        if session.user_id != user_id:
            raise SessionNotFoundException()

        return SessionDetailsResponse(
            session_id=session.id,
            device_name=session.device_name,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            created_at=session.created_at,
            last_active=session.last_active,
            is_active=session.is_active
        )

    @staticmethod
    def get_session_by_refresh_token(db: Session, refresh_token_id: int) -> UserSession | None:

        return SessionRepository.get_by_refresh_token_id(
            db=db,
            refresh_token_id=refresh_token_id,
        )

    @staticmethod
    def get_active_sessions(db: Session, user_id: int) -> list[UserSession]:

        sessions = SessionRepository.get_active_by_user_id(
            db=db,
            user_id=user_id,
        )

        return [
            SessionResponse(
                session_id=session.id,
                device_name=session.device_name,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                created_at=session.created_at,
                last_active=session.last_active,
                is_active=session.is_active,
            )
            for session in sessions
        ]

    @staticmethod
    def get_user_session(db: Session, user_id: int, session_id: UUID) -> UserSession | None:

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
    def update_last_active(db: Session, session_id: UUID) -> UserSession | None:

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
    def revoke_session(db: Session, user_id: int, session_id: UUID) -> bool:

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

        RefreshTokenService.revoke_refresh_token_by_id(
            db=db,
            refresh_token_id=session.refresh_token_id
        )

        return True

    @staticmethod
    def revoke_all_sessions(db: Session, user_id: int) -> MessageResponse:

        active_sessions = (
            SessionRepository.get_active_by_user_id(
                db=db,
                user_id=user_id
            )
        )

        for session in active_sessions:
            RefreshTokenService.revoke_refresh_token_by_id(
                db=db,
                refresh_token_id=session.refresh_token_id
            )

            SessionRepository.revoke(
                db=db,
                session_obj=session
            )

        return MessageResponse(
            message="All sessions revoked successfully."
        )

    @staticmethod
    def update_refresh_token(db: Session, session_obj: UserSession, refresh_token_id : int):

        return SessionRepository.update_refresh_token(
            db = db,
            session_obj=session_obj,
            refresh_token_id=refresh_token_id
        )

    @staticmethod
    def revoke_session_by_refresh_token(db: Session, refresh_token_id: int) -> bool:

        session = (
            SessionRepository.get_by_refresh_token_id(
                db=db,
                refresh_token_id=refresh_token_id
            )
        )

        if not session:
            return False

        SessionRepository.revoke(
            db=db,
            session_obj=session
        )

        return True