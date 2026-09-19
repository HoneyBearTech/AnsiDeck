from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from app.scrub import mask_secret_keys


class RunCreate(BaseModel):
    playbook_id: int
    inventory_id: int
    group_id: int | None = None
    credential_id: int
    vault_password_id: int | None = None
    become: bool = False
    check_mode: bool = False
    diff_mode: bool = False
    limit: str | None = None
    extra_vars: dict[str, Any] | None = None

    @field_validator("limit")
    @classmethod
    def _blank_limit_to_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    playbook_name: str
    inventory_name: str
    group_name: str | None
    credential_name: str
    vault_password_name: str | None
    become: bool
    check_mode: bool
    diff_mode: bool
    limit: str | None
    extra_vars: dict[str, Any] | None
    status: str
    triggered_by: str
    return_code: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    @field_validator("extra_vars")
    @classmethod
    def _mask_secret_looking_values(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return mask_secret_keys(v) if v is not None else None
