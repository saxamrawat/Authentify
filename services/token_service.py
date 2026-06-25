# Token Service

# Libraries

from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext

#Core
from core.security import(
    SECRET_KEY,
    ALGORITHM
)

#Bcrypt Context
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class TokenService:

    @staticmethod
    def create_access_token(username: str, user_id: int, role: str, expire_delta: timedelta):
        encode = {
            "sub": username,
            "id": user_id,
            "role": role,
            "token_type": "access"
        }
        expires = datetime.now(timezone.utc) + expire_delta
        encode.update({"exp": expires})

        return jwt.encode(encode, SECRET_KEY, ALGORITHM)

    @staticmethod
    def create_refresh_token(user_id: int, expire_delta: timedelta):
        encode = {
            "sub": str(user_id),
            "token_type": "refresh"
        }
        expires = datetime.now(timezone.utc) + expire_delta
        encode.update({"exp": expires})

        return jwt.encode(encode, SECRET_KEY, ALGORITHM)

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