import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# A WebAuthn response as the browser returns it (PublicKeyCredential.toJSON()); the library
# checks its structure, this only bounds its size.
_MAX_CREDENTIAL_BYTES = 64 * 1024


def _bounded_credential(value: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(value)) > _MAX_CREDENTIAL_BYTES:
        raise ValueError("the passkey response is too large")
    return value


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
    passkey_count: int = 0
    two_factor_enabled: bool = False
    # REQUIRE_ADMIN_2FA: this session may only set up a second factor (or sign out).
    two_factor_setup_required: bool = False
    # How this session started: SSO sessions re-authenticate by signing in again, not a password.
    signed_in_with: Literal["password", "sso"] = "password"


class MfaChallenge(BaseModel):
    """The password was right; finish signing in with one of `methods`: POST /auth/login/mfa
    (a TOTP or recovery code) or the passkey ceremony (/auth/login/mfa/passkey)."""

    mfa_required: Literal[True] = True
    methods: list[Literal["totp", "passkey", "recovery_code"]] = []


class PasskeyCredentialIn(BaseModel):
    credential: dict[str, Any]

    _bounded = field_validator("credential")(_bounded_credential)


class PasskeyOptionsOut(BaseModel):
    # PublicKeyCredential{Creation,Request}OptionsJSON for navigator.credentials.
    options: dict[str, Any]


class PasskeyOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    last_used_at: datetime | None
    # Synced by its platform (iCloud Keychain, Google Password Manager, ...).
    synced: bool


class PasskeyRegisterRequest(PasskeyCredentialIn):
    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a name is required")
        return v


class PasskeyAddedOut(BaseModel):
    passkey: PasskeyOut
    # Shown once when this is the user's first second factor; None otherwise.
    recovery_codes: list[str] | None = None


class PasskeyRenameRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class SecondFactorProof(BaseModel):
    """A current second factor: a TOTP or recovery code, or a passkey response (to options
    from POST /auth/passkeys/step-up-options)."""

    code: str | None = Field(default=None, max_length=64)
    passkey: dict[str, Any] | None = None

    _bounded = field_validator("passkey")(lambda v: v if v is None else _bounded_credential(v))

    @model_validator(mode="after")
    def _exactly_one(self) -> "SecondFactorProof":
        if (self.code is None) == (self.passkey is None):
            raise ValueError("send either code or passkey")
        return self


class RemovePasskeyRequest(SecondFactorProof):
    current_password: str


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


class TotpDisableRequest(SecondFactorProof):
    current_password: str


class RecoveryCodesOut(BaseModel):
    # None when an earlier second factor already had codes (they stay valid).
    recovery_codes: list[str] | None
