from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class OtpLoginIn(BaseModel):
    token: str = Field(..., min_length=8, max_length=256)


class UserOut(BaseModel):
    id: int
    username: str
    role: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class OtpCreateIn(BaseModel):
    label: Optional[str] = Field(None, max_length=128)
    username: Optional[str] = Field(None, max_length=64, description="If provided, creates the token for this user")


class OtpCreateOut(BaseModel):
    token: str
    expires_in: int