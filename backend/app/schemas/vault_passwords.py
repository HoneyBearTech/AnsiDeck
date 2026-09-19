from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class VaultPasswordCreate(BaseModel):
    name: str
    description: str | None = None
    password: str
    project_id: int | None = None

    @field_validator("password")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("password must not be empty")
        return v


class VaultPasswordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int
    created_at: datetime
