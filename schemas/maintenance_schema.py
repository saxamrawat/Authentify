from pydantic import BaseModel

class CleanupResponse(BaseModel):
    deleted_sessions: int
    deleted_refresh_tokens: int