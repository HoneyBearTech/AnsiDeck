from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.permissions import Role

_USERNAME_PATTERN = r"^[A-Za-z0-9_.@-]+$"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.VIEWER

    @field_validator("password")
    @classmethod
    def _not_username_sized_trivial(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("password must not be blank")
        return v


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=128)


class UserAdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool
    created_by: str | None
    created_at: datetime
