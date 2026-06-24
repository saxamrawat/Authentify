from typing import Annotated
from fastapi import Depends, HTTPException
from starlette import status
from database import SessionLocal
from dependencies.auth import get_current_user
from models import Users

# Admin Authorization Dependency
async def require_admin(current_user: Annotated[Users, Depends(get_current_user)]):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return current_user