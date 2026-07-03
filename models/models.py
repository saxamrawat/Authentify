# Models

# Libraries

from database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

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
    locked_until = Column(DateTime(timezone=True), nullable=True)
    role = Column(String, default="user")
    sessions = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
    )

# Refresh Token Model for Session Tracking
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_token = Column(String)
    expires_at = Column(DateTime(timezone=True))
    is_revoked = Column(Boolean, default=False)
    session = relationship(
        "UserSession",
        back_populates="refresh_token",
        uselist=False
    )

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


# User Session Model

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    device_name = Column(
        String,
        nullable=True,
    )

    ip_address = Column(
        String,
        nullable=True,
    )

    user_agent = Column(
        String,
        nullable=True,
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    last_active = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    user = relationship(
        "Users",
        back_populates="sessions",
    )

    refresh_token_id = Column(
        Integer,
        ForeignKey(
            "refresh_tokens.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        unique=True,
    )

    refresh_token = relationship(
        "RefreshToken",
        back_populates="session"
    )

