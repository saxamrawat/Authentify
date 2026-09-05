# Token Service

# Libraries

from datetime import datetime, timedelta, timezone
from jose import jwt
import hashlib
import uuid

#Core
from core.security import(
    SECRET_KEY,
    ALGORITHM
)

class TokenService:

    @staticmethod
    def create_access_token(username: str, user_id: int, role: str, session_id: str, expire_delta: timedelta):
        issued_at = datetime.now(timezone.utc)
        expires = issued_at + expire_delta

        encode = {
            "sub": username,
            "id": user_id,
            "role": role,
            "session_id": session_id,
            "token_type": "access",
            "jti": str(uuid.uuid4()),
            "iat": issued_at,
            "exp": expires
        }

        return jwt.encode(
            encode,
            SECRET_KEY,
            ALGORITHM
        )

    @staticmethod
    def create_refresh_token(user_id: int, expire_delta: timedelta):
        expires = datetime.now(timezone.utc) + expire_delta

        payload = {
            "sub": str(user_id),
            "token_type": "refresh",
            "jti": str(uuid.uuid4()),
            "exp": expires
        }

        return jwt.encode(payload, SECRET_KEY, ALGORITHM)

    @staticmethod
    def hash_token(token: str) -> str:
        """
        Returns a deterministic SHA-256 hash of the refresh token.

        The raw refresh token is never stored in the database.
        This hash is used for direct database lookup.
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def create_email_verification_token(user_id: int, expire_delta: timedelta):
        encode = {
            "sub": str(user_id),
            "token_type": "email_verification"
        }
        expires = datetime.now(timezone.utc) + expire_delta
        encode.update({"exp": expires})

        return jwt.encode(encode, SECRET_KEY, ALGORITHM)

    @staticmethod
    def create_password_reset_token(user_id: int, expire_delta: timedelta):
        encode = {
            "sub": str(user_id),
            "token_type": "password_reset"
        }
        expires = datetime.now(timezone.utc) + expire_delta
        encode.update({"exp": expires})

        return jwt.encode(encode, SECRET_KEY, ALGORITHM)