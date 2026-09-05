# Maintenance Service

# Libraries
from sqlalchemy.orm import Session

# Schemas
from schemas.maintenance_schema import CleanupResponse

# Services
from services.session_service import SessionService
from services.refresh_token_service import RefreshTokenService


class MaintenanceService:

    @staticmethod
    def cleanup_system_data(db: Session) -> CleanupResponse:

        deleted_refresh_tokens = (
            RefreshTokenService.cleanup_expired_tokens(
                db=db
            )
        )

        deleted_sessions = (
            SessionService.cleanup_revoked_sessions(
                db=db
            )
        )

        return CleanupResponse(
            deleted_sessions=deleted_sessions,
            deleted_refresh_tokens=deleted_refresh_tokens
        )