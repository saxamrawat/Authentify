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
from schemas.session_schema import SessionDashboardResponse
from schemas.maintenance_schema import CleanupResponse

# Repositories
from repositories.session_repository import SessionRepository

# Core
from core.exceptions import (
    SessionNotFoundException,
    SessionAccessDeniedException,
    SessionInvalidException
)
from core.security import ACCESS_TOKEN_EXPIRE_MINUTES

# Services
from services.refresh_token_service import RefreshTokenService
from services.revocation import RevocationStore


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
    def get_active_sessions(db: Session, user_id: int, current_session_id: UUID) -> list[SessionResponse]:

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
                current=(session.id == current_session_id)
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
    def validate_active_session(db: Session, session_id: UUID):
        """
        Validate that a session exists and is still active.

        Raises:
            SessionInvalidException: If the session does not exist or has been revoked.
        """
        session = SessionRepository.get_by_id(
            db=db,
            session_id=session_id
        )

        if not session or not session.is_active:
            raise SessionInvalidException()

        return session

    @staticmethod
    def get_session_dashboard(db: Session, user_id: int, current_session_id: UUID) -> SessionDashboardResponse:

        sessions = SessionRepository.get_active_by_user_id(
            db=db,
            user_id=user_id
        )

        session_responses = [
            SessionResponse(
                session_id=session.id,
                device_name=session.device_name,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                created_at=session.created_at,
                last_active=session.last_active,
                is_active=session.is_active,
                current=(session.id == current_session_id)
            )
            for session in sessions
        ]

        current_session = next(
            (
                session
                for session in session_responses
                if session.current
            ),
            None
        )

        other_sessions = [
            session
            for session in session_responses
            if not session.current
        ]

        return SessionDashboardResponse(
            total_sessions=len(sessions),
            active_sessions=len(sessions),
            current_session=current_session,
            other_sessions=other_sessions
        )

    @staticmethod
    def update_last_active(db: Session, session_id: UUID):
        return SessionRepository.update_last_active(
            db=db,
            session_id=session_id
        )

    @staticmethod
    async def revoke_session(db: Session, user_id: int, session_id: UUID, revocation_store: RevocationStore) -> bool:

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

        await revocation_store.revoke_session(
            session_id=session_id,
            ttl_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60, #(in seconds)
        )

        return True

    @staticmethod
    async def revoke_all_sessions(db: Session, user_id: int, revocation_store: RevocationStore) -> MessageResponse:

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

            await revocation_store.revoke_session(
                session_id=session.id,
                ttl_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60, #(in seconds)
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
    async def revoke_session_by_refresh_token(db: Session, refresh_token_id: int, revocation_store: RevocationStore) -> bool:

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

        await revocation_store.revoke_session(
            session_id=session.id,
            ttl_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60, #(in seconds)
        )

        return True

    @staticmethod
    def cleanup_revoked_sessions(db: Session) -> int:

        return SessionRepository.delete_revoked_sessions(
            db=db
        )