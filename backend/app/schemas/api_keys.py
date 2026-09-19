from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Also used as the key's identity ("apikey:<name>") in run history and the audit log.
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=_NAME_PATTERN)
    preset: Literal["trigger", "read-only"]
    expires_in_days: int = Field(default=90, ge=1, le=365)


class ApiKeyOut(BaseModel):
    id: int
    name: str
    preset: str
    prefix: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    last_used_ip: str | None
    revoked_at: datetime | None
    status: Literal["active", "expired", "revoked"]


class ApiKeyCreated(ApiKeyOut):
    # The only time the plaintext token exists outside the caller's hands.
    token: str
