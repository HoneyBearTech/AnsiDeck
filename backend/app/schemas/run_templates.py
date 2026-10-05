from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import DEFAULT_RUN_TIMEOUT_SECONDS, MAX_RUN_TIMEOUT_SECONDS
from app.scrub import mask_secret_keys


def _blank_to_none(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return v or None


class RunTemplateIn(BaseModel):
    """A template's whole definition (create and update alike). The playbook fixes the
    template's project; everything else must live in it."""

    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    playbook_id: int
    inventory_id: int
    group_name: str | None = Field(None, max_length=255)
    credential_id: int
    vault_password_id: int | None = None
    become: bool = False
    check_mode: bool = False
    diff_mode: bool = False
    limit: str | None = Field(None, max_length=500)
    extra_vars: dict[str, Any] | None = None
    timeout_seconds: int = Field(DEFAULT_RUN_TIMEOUT_SECONDS, ge=1, le=MAX_RUN_TIMEOUT_SECONDS)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("description", "group_name", "limit")
    @classmethod
    def _blank(cls, v: str | None) -> str | None:
        return _blank_to_none(v)


class RunTemplateLaunch(BaseModel):
    """What a launch may change: None keeps the template's own value."""

    limit: str | None = Field(None, max_length=500)
    check_mode: bool | None = None


class RunTemplateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    name: str
    description: str | None
    playbook_id: int | None
    playbook_name: str | None = None
    inventory_id: int | None
    inventory_name: str | None = None
    group_name: str | None
    credential_id: int | None
    credential_name: str | None = None
    vault_password_id: int | None
    vault_password_name: str | None = None
    become: bool
    check_mode: bool
    diff_mode: bool
    limit: str | None
    extra_vars: dict[str, Any] | None
    timeout_seconds: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime
    # Items the template refers to that have been deleted: it can't be launched until edited.
    missing: list[str] = []

    @field_validator("extra_vars")
    @classmethod
    def _mask_secret_looking_values(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return mask_secret_keys(v) if v is not None else None
