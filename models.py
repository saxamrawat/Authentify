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
    is_active = Column(Boolean, default=True)
    role = Column(String)

# Refresh Token Model for Session Tracking
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_token = Column(String)
    expires_at = Column(DateTime(timezone=True))
    is_revoked = Column(Boolean, default=False)
