from typing import Literal

from pydantic import BaseModel, Field, model_validator


class LoginRequest(BaseModel):
    username: str
    password: str


class ProjectAccess(BaseModel):
    id: int
    name: str
    role: str
    permissions: list[str]


class UserOut(BaseModel):
    username: str
    role: str
    # Union across the user's projects (everything for a global admin).
    permissions: list[str]
    projects: list[ProjectAccess]
    totp_enabled: bool


class MfaChallenge(BaseModel):
    """The password was right; POST /auth/login/mfa with a code to finish signing in."""

    mfa_required: Literal[True] = True


class MfaLoginRequest(BaseModel):
    code: str | None = Field(default=None, max_length=16)
    recovery_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _exactly_one(self) -> "MfaLoginRequest":
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("send either code or recovery_code")
        return self


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


class PasswordConfirmRequest(BaseModel):
    current_password: str


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr: str  # SVG data URI


class TotpCodeRequest(BaseModel):
    code: str = Field(max_length=16)


class TotpDisableRequest(BaseModel):
    current_password: str
    # A current TOTP code or one of the recovery codes.
    code: str = Field(max_length=64)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
