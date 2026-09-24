from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator

from app.config import get_settings
from app.permissions import Role

_USERNAME_PATTERN = r"^[A-Za-z0-9_.@-]+$"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.VIEWER
    # Non-admin users act only through project memberships. If omitted and exactly
    # one project exists, the user is added to it with `role`.
    project_id: int | None = None
    # Setting it pre-provisions the user for SSO (matched against the verified email).
    email: EmailStr | None = None

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
    # Only applied when sent; an explicit null clears it.
    email: EmailStr | None = None


class UserAdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool
    created_by: str | None
    created_at: datetime
    email: str | None
    sso_linked: bool
    totp_enabled: bool
    # Only used to name the provider below; the issuer itself isn't sent to the browser.
    sso_issuer: str | None = Field(default=None, exclude=True)

    @computed_field
    @property
    def sso_provider(self) -> str | None:
        if self.sso_issuer is None:
            return None
        return "GitHub" if self.sso_issuer == get_settings().github_url else "SSO"
