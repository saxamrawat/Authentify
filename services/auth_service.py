# Auth Service
# Has some duplicate exceptions need to consolidate.
# Libraries

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from core.device import get_device_name
import hashlib

#Services
from services.token_service import TokenService
from services.session_service import SessionService
from services.refresh_token_service import RefreshTokenService
from services.email_service import EmailService
from services.email_verification_service import EmailVerificationService
from services.password_reset_service import PasswordResetService
from services.revocation import RevocationStore
from services.rate_limiter import RateLimiter, RateLimiterError

# Repositories
from repositories.user_repository import UserRepository

#Schemas
from schemas.auth import CreateUserRequest, ResetPasswordRequest, RefreshRequest,Token, LogOutRequest

#Models
from models.models import Users

#Utils
# from utils.rate_limiter import check_rate_limit

#Core
from core.config import(
    FRONTEND_URL
)
from core.security import(
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    EMAIL_VERIFICATION_EXPIRE_MINUTES,
    PASSWORD_RESET_EXPIRE_MINUTES,
    ACCOUNT_LOCK_DAYS,
    MAX_LOGIN_ATTEMPTS,
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
    SessionSecurityViolationException,
    RateLimiterUnavailableException
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

        email_verification_token = (
            TokenService.create_email_verification_token(
                create_user_model.id,
                timedelta(minutes=EMAIL_VERIFICATION_EXPIRE_MINUTES)
            )
        )

        EmailVerificationService.create_verification_record(
            db=db,
            user_id=create_user_model.id,
            verification_token=email_verification_token
        )

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
    async def login(db: Session, form_data: OAuth2PasswordRequestForm, ip_address: str, user_agent: str | None, rate_limiter: RateLimiter):

        device_name = get_device_name(user_agent)

        ip_identifier = hashlib.sha256(
            ip_address.encode("utf-8")
        ).hexdigest()

        try:
            allowed = await rate_limiter.is_allowed(
                key=f"auth:ratelimit:login:ip:{ip_identifier}",
                limit=5,
                window_seconds=60,
            )

        except RateLimiterError:
            raise RateLimiterUnavailableException()

        if not allowed:
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
            if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(days=ACCOUNT_LOCK_DAYS)
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
    async def refresh_access_token(
            db: Session,
            refresh_request: RefreshRequest,
            revocation_store: RevocationStore,
    ):
        refresh_token = refresh_request.refresh_token

        # Decode JWT
        try:
            payload = jwt.decode(
                refresh_token,
                SECRET_KEY,
                algorithms=[ALGORITHM],
            )
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
        refresh_token_record = RefreshTokenService.get_valid_refresh_token(
            db=db,
            refresh_token=refresh_token,
        )

        if not refresh_token_record:
            raise RefreshTokenNotRecognizedException()

        if refresh_token_record.user_id != user_id:
            raise RefreshTokenNotRecognizedException()

        # Check Expiry
        if refresh_token_record.expires_at < datetime.now(timezone.utc):
            raise RefreshTokenExpiredException()

        # Find the session associated with this refresh token
        user_session = SessionService.get_session_by_refresh_token(
            db=db,
            refresh_token_id=refresh_token_record.id,
        )

        if refresh_token_record.is_revoked:

            # Token belongs to an already revoked/inactive session.
            # This is an expected consequence of session logout.
            if user_session and not user_session.is_active:
                raise SessionSecurityViolationException()

            # Token is revoked but its session is still active.
            # This indicates possible refresh-token reuse.
            # Treat the event as a potential session/account compromise:
            # revoke all persistent refresh tokens and sessions,
            # then propagate session revocation to Redis so existing
            # access tokens are rejected immediately.
            RefreshTokenService.revoke_all_refresh_tokens(
                db=db,
                user_id=user_id,
            )

            await SessionService.revoke_all_sessions(
                db=db,
                user_id=user_id,
                revocation_store=revocation_store,
            )

            raise SessionSecurityViolationException()

        if not user_session:
            raise RefreshTokenNotRecognizedException()

        # If User Session isn't active
        if not user_session.is_active:
            raise SessionSecurityViolationException()

        try:
            # Atomically consume the old refresh token.
            #
            # Only one concurrent request can successfully change the
            # token from active -> revoked.
            consumed = RefreshTokenService.consume_refresh_token(
                db=db,
                refresh_token_id=refresh_token_record.id,
            )

            if not consumed:
                db.rollback()
                raise SessionSecurityViolationException()

            # Generate New Access Token
            user = UserRepository.get_by_id(
                db,
                refresh_token_record.user_id,
            )

            if not user:
                raise UserNotFoundException()

            new_access_token = TokenService.create_access_token(
                username=user.username,
                user_id=int(user_id),
                role=user.role,
                session_id=str(user_session.id),
                expire_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )

            # Refresh Token Rotation
            new_refresh_token = TokenService.create_refresh_token(
                user.id,
                timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            )

            # Create new refresh-token record.
            #
            # This only flushes the INSERT; it does not commit.
            new_refresh_token_record = (
                RefreshTokenService.create_refresh_token_record(
                    db=db,
                    user_id=user.id,
                    refresh_token=new_refresh_token,
                )
            )

            # Update the session to point to the new refresh token.
            #
            # This participates in the current transaction and does
            # not commit independently.
            SessionService.update_refresh_token_in_transaction(
                db=db,
                session_obj=user_session,
                refresh_token_id=new_refresh_token_record.id,
            )

            # Update Last Active inside the same transaction.
            user_session.last_active = datetime.now(timezone.utc)

            # Commit the complete refresh-token rotation atomically.
            db.commit()

        except Exception:
            db.rollback()
            raise

        return Token(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
        )

    @staticmethod
    async def logout(db : Session, logout_request : LogOutRequest, revocation_store: RevocationStore):
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
                refresh_token=refresh_token
            )
        )

        if not refresh_token_record:
            raise RefreshTokenNotRecognizedException()

        if refresh_token_record.user_id != user_id:
            raise RefreshTokenNotRecognizedException()


        await SessionService.revoke_session_by_refresh_token(
            db=db,
            refresh_token_id=refresh_token_record.id,
            revocation_store=revocation_store
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

        if user_id is None:
            raise InvalidTokenException()

        user_id = int(user_id)

        verification_record = (
            EmailVerificationService.get_valid_verification_token(
                db=db,
                verification_token=token,
            )
        )

        if not verification_record:
            raise InvalidTokenException()

        if verification_record.user_id != int(user_id):
            raise InvalidTokenException()

        # Get user
        user = UserRepository.get_by_id(db, user_id)

        if not user:
            raise InvalidTokenException()

        # Mark verified
        user.is_verified = True

        # Cleanup all tokens for this user
        EmailVerificationService.delete_user_tokens(
            db=db,
            user_id=user_id,
        )

        db.add(user)
        db.commit()

        return {"message": "Email verified successfully"}

    @staticmethod
    def request_password_reset(db : Session, email : str):
        user = UserRepository.get_by_email(db, email)

        if not user:
            return {"message": "If the account exists, a reset link has been sent."}

        PasswordResetService.delete_user_tokens(
            db=db,
            user_id=user.id,
        )

        reset_token = TokenService.create_password_reset_token(
            user.id,
            timedelta(minutes=PASSWORD_RESET_EXPIRE_MINUTES)
        )

        PasswordResetService.create_reset_record(
            db=db,
            user_id=user.id,
            reset_token=reset_token,
        )

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

        reset_record = (
            PasswordResetService.get_valid_reset_token(
                db=db,
                reset_token=reset_request.token,
            )
        )

        if not reset_record:
            raise InvalidTokenException()

        if reset_record.user_id != user_id:
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
        PasswordResetService.delete_user_tokens(
            db=db,
            user_id=user_id,
        )

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