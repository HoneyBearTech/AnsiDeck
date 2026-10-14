from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Also used as the key's identity ("apikey:<name>") in run history and the audit log.
_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"


class ApiKeyLimits(BaseModel):
    """Optional limits: None (or leaving it out) means any. The addresses or CIDRs the key may
    be used from; the playbooks and inventories it may start runs of."""

    allowed_networks: list[str] | None = Field(None, max_length=20)
    allowed_playbook_ids: list[int] | None = Field(None, max_length=100)
    allowed_inventory_ids: list[int] | None = Field(None, max_length=100)


class ApiKeyCreate(ApiKeyLimits):
    name: str = Field(min_length=1, max_length=64, pattern=_NAME_PATTERN)
    preset: Literal["trigger", "read-only"]
    expires_in_days: int = Field(default=90, ge=1, le=365)
    # Re-authentication: required unless SSO started this session within the last 15 minutes.
    current_password: str | None = Field(default=None, max_length=128)


class ApiKeyRotate(BaseModel):
    current_password: str | None = Field(default=None, max_length=128)


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
    # suspended: its creator is deactivated, deleted, or can no longer manage this project's keys.
    status: Literal["active", "suspended", "expired", "revoked"]
    suspended_because: str | None = None
    allowed_networks: list[str] | None = None
    # The allowed playbooks and inventories as {id, name}; a deleted one is left out.
    allowed_playbooks: list[dict] | None = None
    allowed_inventories: list[dict] | None = None


class ApiKeyCreated(ApiKeyOut):
    # The only time the plaintext token exists outside the caller's hands.
    token: str
