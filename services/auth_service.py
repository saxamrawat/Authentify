# Auth Service
# Has some duplicate exceptions need to consolidate.
# Libraries

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError

#Services
from services.token_service import TokenService
from services.session_service import SessionService
from services.refresh_token_service import RefreshTokenService
from services.email_service import EmailService

# Repositories
from repositories.user_repository import UserRepository
from repositories.refresh_token_repository import RefreshTokenRepository
from repositories.email_verification_repository import EmailVerificationRepository
from repositories.password_reset_repository import PasswordResetRepository

#Schemas
from schemas.auth import CreateUserRequest, ResetPasswordRequest, RefreshRequest,Token, LogOutRequest

#Models
from models.models import Users, EmailVerification, PasswordReset

#Utils
from utils.rate_limiter import check_rate_limit

#Core
from core.config import(
    FRONTEND_URL
)
from core.security import(
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS
)
from core.exceptions import (
    InvalidCredentialsException,
    UserLockedException,
    UserNotFoundException,
    InvalidTokenException,
    InvalidTokenTypeException,
    EmailAlreadyRegisteredException,
    UsernameAlreadyTakenException,
    EmailDeliveryFailedException,
    TooManyLoginAttemptsException,
    RefreshTokenExpiredException,
    RefreshTokenNotRecognizedException,
    SessionSecurityViolationException
)

# Authentication and Hashed Password Dependencies
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:

    @staticmethod
    def register_user(db: Session, create_user_request : CreateUserRequest):
        # Normalize inputs
        normalized_email = create_user_request.email.lower().strip()
        normalized_username = create_user_request.username.lower().strip()

        # Check existing email
        existing_email = UserRepository.get_by_email(db, normalized_email)

        if existing_email:
            raise EmailAlreadyRegisteredException()

        # Check existing username
        existing_username = UserRepository.get_by_username(db, normalized_username)

        if existing_username:
            raise UsernameAlreadyTakenException()

        create_user_model = Users(
            email=normalized_email,
            username=normalized_username,
            first_name=create_user_request.first_name,
            last_name=create_user_request.last_name,
            hashed_password=bcrypt_context.hash(create_user_request.password),
        )

        db.add(create_user_model)
        db.commit()

        # Retrieving User
        db.refresh(create_user_model)

        # Creating and Hashing Email Verification Token
        email_verification_token = TokenService.create_email_verification_token(create_user_model.id, timedelta(minutes=15))

        hashed_email_token = bcrypt_context.hash(email_verification_token)

        # Creating and committing an entry to the DB
        email_verification_model = EmailVerification(
            user_id=create_user_model.id,
            hashed_token=hashed_email_token,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
        )

        db.add(email_verification_model)
        db.commit()

        # Sending Verification Email to User
        frontend_url = FRONTEND_URL

        verification_link = (
            f"{frontend_url}/verify-email"
            f"?token={email_verification_token}"
        )
        try:
            EmailService.send_verification_email(
                create_user_model.email,
                verification_link
            )
        except Exception as e:
            print(e)
            raise EmailDeliveryFailedException()

    @staticmethod
    def login(db : Session, form_data: OAuth2PasswordRequestForm, ip_address : str, user_agent : str | None):

        device_name = user_agent

        if not check_rate_limit(ip_address, 5, timedelta(minutes=1)):
            raise TooManyLoginAttemptsException()

        normalized_username = form_data.username.lower().strip()

        # Get User
        user = UserRepository.get_by_username(db, normalized_username)

        if not user:
            raise InvalidCredentialsException()

        # Verified or not
        if not user.is_verified:
            raise InvalidCredentialsException()

        # Check is_locked/locked_until
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise UserLockedException()
        else:
            user.locked_until = None

        # authenticate user
        if not bcrypt_context.verify(form_data.password, user.hashed_password):
            user.failed_attempts += 1
            if user.failed_attempts >= 3:
                user.locked_until = datetime.now(timezone.utc) + timedelta(days=3)
                RefreshTokenService.revoke_all_refresh_tokens(db, user.id)
            db.add(user)
            db.commit()
            raise InvalidCredentialsException()
        user.failed_attempts = 0
        db.add(user)
        db.commit()

        # Creating refresh tokens
        refresh_token = TokenService.create_refresh_token(user.id, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

        # Creating New Refresh Token

        refresh_token_record = RefreshTokenService.create_refresh_token_record(
            db=db,
            user_id=user.id,
            refresh_token=refresh_token
        )

        # Creating Device Session
        session = SessionService.create_session(
            db=db,
            user_id=user.id,
            refresh_token_id=refresh_token_record.id,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Creating Access Token
        access_token = TokenService.create_access_token(
            username=user.username,
            user_id=user.id,
            role=user.role,
            session_id=str(session.id),
            expire_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Returning the Token Model
        return Token(
            access_token = access_token,
            refresh_token = refresh_token,
            token_type = "bearer"
        )

    @staticmethod
    def refresh_access_token(db: Session, refresh_request : RefreshRequest):
        refresh_token = refresh_request.refresh_token
        # Decode JWT
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise RefreshTokenNotRecognizedException()

        # Validate Token type
        if payload.get("token_type") != "refresh":
            raise InvalidTokenTypeException()

        user_id = payload.get("sub")

        if user_id is None:
            raise RefreshTokenNotRecognizedException()

        user_id = int(user_id)

        # Find Matching Refresh Token in DB

        refresh_token_record = (
            RefreshTokenService.get_valid_refresh_token(
                db=db,
                user_id=user_id,
                refresh_token=refresh_token
            )
        )

        if not refresh_token_record:
            raise RefreshTokenNotRecognizedException()

        # Check Expiry
        if refresh_token_record.expires_at < datetime.now(timezone.utc):
            raise RefreshTokenExpiredException()

        # Reuse Detection
        if refresh_token_record.is_revoked:
            RefreshTokenService.revoke_all_refresh_tokens(db, user_id)
            SessionService.revoke_all_sessions(db, user_id)
            raise SessionSecurityViolationException()

        user_session = (
            SessionService.get_session_by_refresh_token(
                db=db,
                refresh_token_id=refresh_token_record.id
            )
        )

        if not user_session:
            raise RefreshTokenNotRecognizedException()

        # If User Session isn't active
        if not user_session.is_active:
            raise SessionSecurityViolationException()


        # Revoking old refresh token
        RefreshTokenService.revoke_refresh_token(db, refresh_token_record)

        # Generate New Access Token
        user = UserRepository.get_by_id(db, refresh_token_record.user_id)
        if not user:
            raise UserNotFoundException()

        new_access_token = TokenService.create_access_token(
            username=user.username,
            user_id=int(user_id),
            role=user.role,
            session_id=str(user_session.id),
            expire_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Refresh Token Rotation

        new_refresh_token = TokenService.create_refresh_token(user.id, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

        #Creating new Refresh Token
        new_refresh_token_record = RefreshTokenService.create_refresh_token_record(
            db=db,
            user_id=user.id,
            refresh_token=new_refresh_token
        )

        # Updating Refresh Token for the session
        SessionService.update_refresh_token(
            db=db,
            session_obj=user_session,
            refresh_token_id=new_refresh_token_record.id
        )

        # Update Last Active
        SessionService.update_last_active(
            db=db,
            session_id=user_session.id
        )

        return Token(
            access_token = new_access_token,
            refresh_token = new_refresh_token,
            token_type = "bearer"
        )

    @staticmethod
    def logout(db : Session, logout_request : LogOutRequest):
        refresh_token = logout_request.refresh_token

        # decode token
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise RefreshTokenNotRecognizedException()

        # Validate Token type
        if payload.get("token_type") != "refresh":
            raise InvalidTokenTypeException()

        user_id = payload.get("sub")

        if user_id is None:
            raise InvalidTokenException()

        user_id = int(user_id)

        # Getting the refresh token and revoking the user session
        refresh_token_record = (
            RefreshTokenService.get_valid_refresh_token(
                db=db,
                user_id=user_id,
                refresh_token=refresh_token
            )
        )

        SessionService.revoke_session_by_refresh_token(
            db=db,
            refresh_token_id=refresh_token_record.id
        )

        # Revoke Current Refresh Token
        RefreshTokenService.revoke_refresh_token(
            db=db,
            refresh_token_record=refresh_token_record
        )

        return {"message": "Logout Successful"}

    @staticmethod
    def verify_email(db : Session, token : str):
        # Decode JWT
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise InvalidTokenException()

        # Check token type
        if payload.get("token_type") != "email_verification":
            raise InvalidTokenException()

        user_id = payload.get("sub")

        # Find matching token in DB
        tokens = EmailVerificationRepository.get_user_tokens(db, user_id)

        valid_token = None

        for t in tokens:
            if bcrypt_context.verify(token, t.hashed_token):
                valid_token = t
                break

        if not valid_token:
            raise InvalidTokenException()

        # Check expiry
        if valid_token.expires_at < datetime.now(timezone.utc):
            raise InvalidTokenException()

        # Get user
        user = UserRepository.get_by_id(db, user_id)
        if not user:
            raise InvalidTokenException()

        # Mark verified
        user.is_verified = True

        # Cleanup all tokens for this user
        EmailVerificationRepository.delete_user_tokens(db, user_id)

        db.add(user)
        db.commit()

        return {"message": "Email verified successfully"}

    @staticmethod
    def request_password_reset(db : Session, email : str):
        user = UserRepository.get_by_email(db, email)

        if not user:
            return {"message": "If the account exists, a reset link has been sent."}

        PasswordResetRepository.delete_user_tokens(db, user.id)
        db.commit()

        reset_token = TokenService.create_password_reset_token(user.id, timedelta(minutes=15))
        hashed_reset_token = bcrypt_context.hash(reset_token)
        password_reset_model = PasswordReset(
            user_id=user.id,
            hashed_token=hashed_reset_token,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
        )

        db.add(password_reset_model)
        db.commit()

        # Send email for Password Reset
        frontend_url = FRONTEND_URL

        reset_link = (
            f"{frontend_url}/reset-password"
            f"?token={reset_token}"
        )
        try:
            EmailService.send_password_reset_email(
                user.email,
                reset_link
            )
        except Exception:
            raise EmailDeliveryFailedException()

        return {"message": "If the account exists, a reset link has been sent."}

    @staticmethod
    def reset_password(db: Session, reset_request: ResetPasswordRequest):
        # Decode Token
        try:
            payload = jwt.decode(reset_request.token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise InvalidTokenException()

        # Validate Token Type

        if not payload.get("token_type") == "password_reset":
            raise InvalidTokenException()

        # find matching DB token
        user_id = payload.get("sub")

        if user_id is None:
            raise InvalidTokenException()

        user_id = int(user_id)

        tokens = PasswordResetRepository.get_user_tokens(db, user_id)
        valid_token = None

        for t in tokens:
            if bcrypt_context.verify(reset_request.token, t.hashed_token):
                valid_token = t
                break

        if not valid_token:
            raise InvalidTokenException()

        # check expiry
        if valid_token.expires_at < datetime.now(timezone.utc):
            raise InvalidTokenException()
        # find user
        user = UserRepository.get_by_id(db, user_id)
        if not user:
            raise InvalidTokenException()
        # hash new password
        hashed_new_password = bcrypt_context.hash(reset_request.new_password)
        # update password
        user.hashed_password = hashed_new_password

        # delete reset tokens
        PasswordResetRepository.delete_user_tokens(db, user_id)

        # invalidate Refresh Token
        RefreshTokenService.revoke_all_refresh_tokens(db, user_id)
        # reset user state
        user.failed_attempts = 0
        user.locked_until = None

        db.add(user)
        db.commit()

        return {"message": "Password Reset Successful"}

    @staticmethod
    def get_me(current_user : Users):
        return {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "role": current_user.role
        }