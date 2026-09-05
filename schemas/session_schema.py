# Session Schema

# Libraries

from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class SessionResponse(BaseModel):
    session_id: UUID
    device_name: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_active: datetime
    is_active: bool
    current: bool

    class Config:
        from_attributes = True

class MessageResponse(BaseModel):
    message: str

class SessionDetailsResponse(BaseModel):
    session_id: UUID
    device_name: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_active: datetime
    is_active: bool

    class Config:
        from_attributes = True

class SessionDashboardResponse(BaseModel):
    total_sessions: int
    active_sessions: int
    current_session: SessionResponse | None
    other_sessions: list[SessionResponse]