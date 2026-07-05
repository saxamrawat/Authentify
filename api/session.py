# Session Router


# Libraries
from fastapi import APIRouter, Depends
from uuid import UUID

# Dependencies
from dependencies.database import db_dependency
from dependencies.auth import get_current_user

# Services
from services.session_service import SessionService

# Schemas
from schemas.session_schema import SessionResponse
from schemas.session_schema import MessageResponse
from schemas.session_schema import SessionDetailsResponse


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"]
)

@router.get("", response_model=list[SessionResponse])
def get_active_sessions( db: db_dependency, current_user=Depends(get_current_user)):
    return SessionService.get_active_sessions(
        db=db,
        user_id=current_user.id
    )

@router.get("/{session_id}", response_model=SessionDetailsResponse)
def get_session_details(db: db_dependency, session_id: UUID, current_user=Depends(get_current_user)):
    return SessionService.get_session_details(
        db=db,
        user_id=current_user.id,
        session_id=session_id
    )

@router.post("/logout-all", response_model=MessageResponse)
def logout_all_devices(db: db_dependency, current_user=Depends(get_current_user)):
    return SessionService.revoke_all_sessions(
        db=db,
        user_id=current_user.id
    )

@router.delete("/{session_id}")
def revoke_session(db: db_dependency, session_id: UUID, current_user=Depends(get_current_user)):
    return SessionService.revoke_session(
        db=db,
        user_id=current_user.id,
        session_id=session_id
    )



