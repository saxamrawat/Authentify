from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Query
from typing import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users, RefreshToken, EmailVerification, PasswordReset
from dependencies.permissions import get_current_user
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import os
from dotenv import load_dotenv

# Authentication and Hashed Password Dependencies
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/login")
load_dotenv()
SECRET_KEY = os.getenv("SECRET_AUTH_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# DB dependency function
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

#Token Creation Functions

def create_access_token(username : str, user_id : int, role : str, expire_delta : timedelta):
    encode = {
        "sub" : username,
        "id" : user_id,
        "role" : role,
        "token_type" : "access"
    }
    expires = datetime.now(timezone.utc) + expire_delta
    encode.update({"exp" : expires})

    return jwt.encode(encode, SECRET_KEY, ALGORITHM)

def create_refresh_token(user_id : int, expire_delta : timedelta):
    encode = {
        "sub": str(user_id),
        "token_type" : "refresh"
    }
    expires = datetime.now(timezone.utc) + expire_delta
    encode.update({"exp": expires})

    return jwt.encode(encode, SECRET_KEY, ALGORITHM)

def create_email_verification_token(user_id: int, expire_delta : timedelta):
    encode = {
        "sub" : str(user_id),
        "token_type" : "email_verification"
    }
    expires = datetime.now(timezone.utc) + expire_delta
    encode.update({"exp" : expires})

    return jwt.encode(encode, SECRET_KEY, ALGORITHM)

def create_password_reset_token(user_id: int, expire_delta : timedelta):
    encode = {
        "sub" : str(user_id),
        "token_type" : "password_reset"
    }
    expires = datetime.now(timezone.utc) + expire_delta
    encode.update({"exp" : expires})

    return jwt.encode(encode, SECRET_KEY, ALGORITHM)

# Session Revoking Functions

def revoke_current_session(refresh_token : str, user_id : int, db : db_dependency):
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user_id).filter(
        RefreshToken.is_revoked == False).all()

    valid_token = None

    for token in tokens:
        if bcrypt_context.verify(refresh_token, token.hashed_token):
            valid_token = token
            break

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh Token not recognized")

    valid_token.is_revoked = True

    db.commit()

def revoke_all_sessions(user_id: int, db : db_dependency):
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user_id).filter(RefreshToken.is_revoked == False).all()

    for token in tokens:
        token.is_revoked = True

    db.commit()