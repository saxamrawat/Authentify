from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from typing import Annotated
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users, RefreshToken
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import os
from dotenv import load_dotenv
from typing_extensions import deprecated

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
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

# Pydantics Classes

class CreateUserRequest(BaseModel):
    username : str
    email : str
    first_name : str
    last_name : str
    password : str
    role : str

class RefreshRequest(BaseModel):
    refresh_token : str

class Token(BaseModel):
    access_token : str
    refresh_token : str
    token_type : str

# Helper Functions

def authenticate_user(username : str, password : str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(username : str, user_id : int, expire_delta : timedelta):
    encode = {
        "sub" : username,
        "id" : user_id,
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

async def get_current_user(token : Annotated[str, Depends(oauth2_bearer)], db : db_dependency):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("token_type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token Type")

        username: str = payload.get("sub")
        user_id: str = int(payload.get("id"))

        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")

        user = db.query(Users).filter(Users.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

        return user

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")


# CRUD Operations

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request : CreateUserRequest, db: db_dependency):
    create_user_model = Users(
        email  = create_user_request.email,
        username = create_user_request.username,
        first_name = create_user_request.first_name,
        last_name = create_user_request.last_name,
        role=create_user_request.role,
        hashed_password= bcrypt_context.hash(create_user_request.password),
        is_active=True
    )

    db.add(create_user_model)
    db.commit()

@router.post("/login", response_model=Token)
async def login_for_access_token(form_data : Annotated[OAuth2PasswordRequestForm, Depends()], db : db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user.")

    # Creating both access and refresh tokens
    access_token = create_access_token(user.username, user.id, timedelta(minutes=1))
    refresh_token = create_refresh_token(user.id, timedelta(days=2))
    # Hashing refresh token
    hashed_refresh = bcrypt_context.hash(refresh_token)
    # Storing refresh token in db
    refresh_token_model = RefreshToken(
        user_id = user.id,
        hashed_token = hashed_refresh,
        expires_at = datetime.now(timezone.utc) + timedelta(days=2),
        is_revoked = False
    )
    db.add(refresh_token_model)
    db.commit()

    # Returning the Token Model
    return {
        "access_token" : access_token,
        "refresh_token" : refresh_token,
        "token_type" : "bearer"
    }

@router.post("/refresh", response_model=Token)
async def refresh_for_refresh_token(request : RefreshRequest, db : db_dependency):
    refresh_token = request.refresh_token

    # Decode JWT
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="-Invalid refresh token")

    # Validate Token type
    if payload.get("token_type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = int(payload.get("sub"))

    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Find Matching Token in DB
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user_id).filter(RefreshToken.is_revoked == False).all()

    valid_token = None

    for token in tokens:
        if bcrypt_context.verify(refresh_token, token.hashed_token):
            valid_token = token
            break

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh Token not recognized")

    # Check Expiry
    if valid_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh Token Expired")

    # Generate New Access Token
    user = db.query(Users).filter(Users.id == valid_token.user_id).first()
    new_access_token = create_access_token(
        username = user.username,
        user_id = int(user_id),
        expire_delta= timedelta(minutes=1)
    )

    return {
        "access_token" : new_access_token,
        "refresh_token" : refresh_token,
        "token_type" : "bearer"
    }

@router.get("/me")
async def get_me(current_user : Annotated[Users, Depends(get_current_user)]):
    return {
        "id" : current_user.id,
        "username" : current_user.username,
        "email" : current_user.email
    }