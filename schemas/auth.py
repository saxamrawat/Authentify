from pydantic import BaseModel, EmailStr, Field, field_validator
import re

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