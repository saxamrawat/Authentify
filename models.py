from database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime


# User Data Model
class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    username = Column(String, unique=True)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String)
    is_verified = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    role = Column(String, default="user")

# Refresh Token Model for Session Tracking
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_token = Column(String)
    expires_at = Column(DateTime(timezone=True))
    is_revoked = Column(Boolean, default=False)

#Email Verification Model
class EmailVerification(Base):
    __tablename__ = "email_verification"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_token = Column(String)
    expires_at = Column(DateTime(timezone=True))

#Password Reset Model
class PasswordReset(Base):
    __tablename__ = "password_reset"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_token = Column(String)
    expires_at = Column(DateTime(timezone=True))
