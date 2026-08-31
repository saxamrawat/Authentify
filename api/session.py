# Session Router


# Libraries
from fastapi import APIRouter, Depends
from uuid import UUID
from typing import Annotated

# Dependencies
from dependencies.database import db_dependency
from dependencies.auth import get_current_user
from dependencies.auth import get_current_session_id
from dependencies.redis import get_revocation_store

# Services
from services.session_service import SessionService
from services.revocation import RevocationStore

# Schemas
from schemas.session_schema import SessionResponse
from schemas.session_schema import MessageResponse
from schemas.session_schema import SessionDetailsResponse
from schemas.session_schema import SessionDashboardResponse


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"]
)

@router.get("", response_model=list[SessionResponse])
def get_active_sessions( db: db_dependency, current_session_id: Annotated[UUID, Depends(get_current_session_id)], current_user=Depends(get_current_user)):
    return SessionService.get_active_sessions(
        db=db,
        user_id=current_user.id,
        current_session_id=current_session_id
    )

@router.get("/dashboard", response_model=SessionDashboardResponse)
def get_session_dashboard(db: db_dependency, current_session_id: Annotated[UUID, Depends(get_current_session_id)], current_user=Depends(get_current_user)):
    return SessionService.get_session_dashboard(
        db=db,
        user_id=current_user.id,
        current_session_id=current_session_id
    )

@router.get("/{session_id}", response_model=SessionDetailsResponse)
def get_session_details(db: db_dependency, session_id: UUID, current_user=Depends(get_current_user)):
    return SessionService.get_session_details(
        db=db,
        user_id=current_user.id,
        session_id=session_id
    )

@router.post("/logout-all", response_model=MessageResponse)
async def logout_all_devices(db: db_dependency, current_user=Depends(get_current_user), revocation_store: RevocationStore = Depends(get_revocation_store)):
    return await SessionService.revoke_all_sessions(
        db=db,
        user_id=current_user.id,
        revocation_store=revocation_store,
    )

@router.delete("/{session_id}")
async def revoke_session(db: db_dependency, session_id: UUID, current_user=Depends(get_current_user), revocation_store: RevocationStore = Depends(get_revocation_store)):
    return await SessionService.revoke_session(
        db=db,
        user_id=current_user.id,
        session_id=session_id,
        revocation_store=revocation_store,
    )