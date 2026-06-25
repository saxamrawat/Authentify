# Auth Dependencies

# Libraries

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timezone
from starlette import status
from sqlalchemy.orm import Session
from typing import Annotated
from dependencies.database import get_db
from jose import JWTError, jwt
from repositories.user_repository import UserRepository

# JWT Config
from core.security import(
    SECRET_KEY,
    ALGORITHM
)

oauth2_bearer = OAuth2PasswordBearer(
    tokenUrl="auth/login"
)

# Current User Dependency
async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Validate token type
        if payload.get("token_type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")
        username = payload.get("sub")
        user_id = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")
        # Find user
        user = UserRepository.get_by_id(db, user_id)

        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
        # Check account lock
        if (user.locked_until and user.locked_until > datetime.now(timezone.utc)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User temporarily locked.")
        return user

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")