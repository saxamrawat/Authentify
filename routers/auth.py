from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Query, APIRouter, Depends, Request
from typing import Annotated
from pydantic import BaseModel, EmailStr, Field, field_validator
import re
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users, RefreshToken, EmailVerification, PasswordReset
from dependencies.permissions import get_current_user
from utils.token_utils import create_access_token, create_refresh_token, create_email_verification_token, create_password_reset_token, revoke_current_session, revoke_all_sessions
from utils.email_utils import send_verification_email, send_password_reset_email
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import os
from dotenv import load_dotenv

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
    username: str = Field(min_length=3, max_length=20)
    email: EmailStr
    first_name: str = Field(min_length=2, max_length=30)
    last_name: str = Field(min_length=2, max_length=30)
    password: str = Field(min_length=8, max_length=64)

    # Username Validation
    @field_validator("username")
    @classmethod
    def validate_username(cls, value):

        value = value.strip().lower()

        if not re.match(r"^[a-zA-Z0-9_]+$", value):
            raise ValueError(
                "Username can only contain letters, numbers, and underscores."
            )

        return value

    # Password Validation
    @field_validator("password")
    @classmethod
    def validate_password(cls, value):

        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "Password must contain at least one uppercase letter."
            )

        if not re.search(r"[a-z]", value):
            raise ValueError(
                "Password must contain at least one lowercase letter."
            )

        if not re.search(r"[0-9]", value):
            raise ValueError(
                "Password must contain at least one number."
            )

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError(
                "Password must contain at least one special character."
            )

        return value

    # Email Normalization
    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().lower()

    # Name Cleanup
    @field_validator("first_name", "last_name")
    @classmethod
    def clean_names(cls, value):
        return value.strip()

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=64)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value):

        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "Password must contain at least one uppercase letter."
            )

        if not re.search(r"[a-z]", value):
            raise ValueError(
                "Password must contain at least one lowercase letter."
            )

        if not re.search(r"[0-9]", value):
            raise ValueError(
                "Password must contain at least one number."
            )

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError(
                "Password must contain at least one special character."
            )

        return value

class RefreshRequest(BaseModel):
    refresh_token : str

class Token(BaseModel):
    access_token : str
    refresh_token : str
    token_type : str

class LogOutRequest(BaseModel):
    refresh_token : str

# Helper Functions

def check_user(username: str, db):

    normalized_username = username.lower().strip()

    user = db.query(Users).filter(
        Users.username == normalized_username
    ).first()

    if not user:
        return None

    return user

# In-Memory Rate Limiter
rate_limiter = {}

def check_rate_limit(ip: str, limit: int, window: timedelta):

    current_time = datetime.now(timezone.utc)

    # Create IP bucket
    if ip not in rate_limiter:
        rate_limiter[ip] = []

    # Remove expired timestamps
    rate_limiter[ip] = [
        timestamp
        for timestamp in rate_limiter[ip]
        if current_time - timestamp < window
    ]

    # Remove empty IPs (optional cleanup)
    if len(rate_limiter[ip]) == 0:
        rate_limiter.pop(ip, None)
        rate_limiter[ip] = []

    # Rate limit exceeded
    if len(rate_limiter[ip]) >= limit:
        return False

    # Store current request timestamp
    rate_limiter[ip].append(current_time)

    return True


# CRUD Operations

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request : CreateUserRequest, db: db_dependency):
    # Normalize inputs
    normalized_email = create_user_request.email.lower().strip()
    normalized_username = create_user_request.username.lower().strip()

    # Check existing email
    existing_email = db.query(Users).filter(
        Users.email == normalized_email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered."
        )

    # Check existing username
    existing_username = db.query(Users).filter(
        Users.username == normalized_username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken."
        )
    create_user_model = Users(
        email=normalized_email,
        username=normalized_username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(create_user_model)
    db.commit()

    #Retrieving User
    db.refresh(create_user_model)

    #Creating and Hashing Email Verification Token
    email_verification_token = create_email_verification_token(create_user_model.id, timedelta(minutes=15))

    hashed_email_token = bcrypt_context.hash(email_verification_token)

    #Creating and committing an entry to the DB
    email_verification_model = EmailVerification(
        user_id = create_user_model.id,
        hashed_token = hashed_email_token,
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    )

    db.add(email_verification_model)
    db.commit()

    #Sending Verification Email to User
    frontend_url = os.getenv("FRONTEND_URL")

    verification_link = (
        f"{frontend_url}/verify-email"
        f"?token={email_verification_token}"
    )
    try:
        send_verification_email(
            create_user_model.email,
            verification_link
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=500,
            detail="Failed to send verification email"
        )

@router.post("/login", response_model=Token)
async def login_for_access_token(request : Request, form_data : Annotated[OAuth2PasswordRequestForm, Depends()], db : db_dependency):
    ip = request.client.host

    if not check_rate_limit(ip, 5, timedelta(minutes=1)):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts. Try again later.")

    normalized_username = form_data.username.lower().strip()
    user = check_user(normalized_username, db)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    #Verified or not
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    #Check is_locked/locked_until
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User temporarily locked.")
    else:
        user.locked_until = None

    #authenticate user
    if not bcrypt_context.verify(form_data.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
            revoke_all_sessions(user.id, db)
        db.add(user)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    user.failed_attempts = 0
    db.add(user)
    db.commit()

    # Creating both access and refresh tokens
    access_token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))
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
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user_id).all()

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

    # Reuse Detection
    if valid_token.is_revoked:
        revoke_all_sessions(user_id, db)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session Security Violation Detected.")

    # Revoking old refresh token
    valid_token.is_revoked = True

    # Generate New Access Token
    user = db.query(Users).filter(Users.id == valid_token.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    new_access_token = create_access_token(
        username = user.username,
        user_id = int(user_id),
        role = user.role,
        expire_delta= timedelta(minutes=20)
    )

    #Refresh Token Rotation

    new_refresh_token = create_refresh_token(user.id, timedelta(days=2))
    # Hashing refresh token
    hashed_refresh = bcrypt_context.hash(new_refresh_token)
    # Storing refresh token in db
    refresh_token_model = RefreshToken(
        user_id=user.id,
        hashed_token=hashed_refresh,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2),
        is_revoked=False
    )
    db.add(refresh_token_model)
    db.commit()

    return {
        "access_token" : new_access_token,
        "refresh_token" : new_refresh_token,
        "token_type" : "bearer"
    }

#Logout
@router.post("/logout")
async def logout(logout_request : LogOutRequest, db : db_dependency):
    refresh_token = logout_request.refresh_token

    #decode token
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Validate Token type
    if payload.get("token_type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = int(payload.get("sub"))

    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Revoke Current Session
    revoke_current_session(refresh_token, user_id, db)

    return {"message" : "Logout Successful"}


# Email Verification Endpoints

@router.get("/verify-email")
async def verify_email(token: str, db: db_dependency):
    # Decode JWT
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Check token type
    if payload.get("token_type") != "email_verification":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = payload.get("sub")

    # Find matching token in DB
    tokens = db.query(EmailVerification).filter(EmailVerification.user_id == user_id).all()
    valid_token = None

    for t in tokens:
        if bcrypt_context.verify(token, t.hashed_token):
            valid_token = t
            break

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Check expiry
    if valid_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Get user
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Mark verified
    user.is_verified = True

    # Cleanup all tokens for this user
    db.query(EmailVerification).filter(EmailVerification.user_id == user_id).delete()

    db.add(user)
    db.commit()

    return {"message": "Email verified successfully"}

# Password Reset Endpoints

@router.post("/request-password-reset")
async def request_password_reset(email : str, db :db_dependency):
    user = db.query(Users).filter(Users.email == email).first()

    if not user:
        return {"message": "If the account exists, a reset link has been sent."}

    db.query(PasswordReset).filter(PasswordReset.user_id == user.id).delete()
    db.commit()

    reset_token = create_password_reset_token(user.id, timedelta(minutes=15))
    hashed_reset_token = bcrypt_context.hash(reset_token)
    password_reset_model = PasswordReset(
        user_id = user.id,
        hashed_token = hashed_reset_token,
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    )

    db.add(password_reset_model)
    db.commit()

    #Send email for Password Reset
    frontend_url = os.getenv("FRONTEND_URL")

    reset_link = (
        f"{frontend_url}/reset-password"
        f"?token={reset_token}"
    )
    try:
        send_password_reset_email(
            user.email,
            reset_link
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to send password reset email"
        )

    return {"message" : "If the account exists, a reset link has been sent."}


@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: db_dependency):
    # Decode Token
    try:
        payload = jwt.decode(request.token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Validate Token Type

    if not payload.get("token_type") == "password_reset":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # find matching DB token
    user_id = int(payload.get("sub"))

    tokens = db.query(PasswordReset).filter(PasswordReset.user_id == user_id).all()
    valid_token = None

    for t in tokens:
        if bcrypt_context.verify(request.token, t.hashed_token):
            valid_token = t
            break

    if not valid_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # check expiry
    if valid_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    # find user
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    # hash new password
    hashed_new_password = bcrypt_context.hash(request.new_password)
    # update password
    user.hashed_password = hashed_new_password

    # delete reset tokens
    db.query(PasswordReset).filter(PasswordReset.user_id == user_id).delete()

    # invalidate sessions(recommended) i.e. removing for Refresh Tokens
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()

    # reset user state
    user.failed_attempts = 0
    user.locked_until = None

    db.add(user)
    db.commit()

    return {"message" : "Password Reset Successful"}

#Protected Routes
@router.get("/me")
async def get_me(current_user : Annotated[Users, Depends(get_current_user)]):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "role": current_user.role
    }