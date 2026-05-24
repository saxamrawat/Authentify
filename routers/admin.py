from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from dependencies.permissions import get_current_user, require_admin

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)

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
    username = username.lower().strip()
    user = db.query(Users).filter(Users.username == username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
    db.commit()

    return {"message" : "User Locked"}

@router.post("/{username}/unlock")
async def unlock_user_account(admin_user : Annotated[Users, Depends(require_admin)], username : str, db : db_dependency):
    username = username.lower().strip()
    user = db.query(Users).filter(Users.username == username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    return {"message" : "User Unlocked"}

@router.post("/{username}/role")
async def change_user_role(admin_user : Annotated[Users, Depends(require_admin)], username : str, role : str, db : db_dependency):
    username = username.lower().strip()
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