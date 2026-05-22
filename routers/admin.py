from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Query
from typing import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import Nullable
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users, RefreshToken, EmailVerification, PasswordReset
from dependencies.permissions import get_current_user, require_admin
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import os
from dotenv import load_dotenv

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)

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

@router.get("/users")
async def get_all_users(admin_user : Annotated[Users, Depends(require_admin)], db : db_dependency):
    users = db.query(Users).all()
    return users

@router.post("/{username}/lock")
async def lock_user_account(admin_user : Annotated[Users, Depends(require_admin)], username : str, db : db_dependency):
    user = db.query(Users).filter(Users.username == username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.is_locked = True
    user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
    db.commit()

    return {"message" : "User Locked"}

@router.post("/{username}/unlock")
async def unlock_user_account(admin_user : Annotated[Users, Depends(require_admin)], username : str, db : db_dependency):
    user = db.query(Users).filter(Users.username == username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.is_locked = False
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    return {"message" : "User Unlocked"}

@router.post("/{username}/role")
async def change_user_role(admin_user : Annotated[Users, Depends(require_admin)], username : str, role : str, db : db_dependency):
    user = db.query(Users).filter(Users.username == username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if role not in ["admin", "user"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong user role provided.")

    if user.username == admin_user.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Can't Self Demote.")

    user.role = role
    db.commit()
    return {"message" : "User Role Changed."}