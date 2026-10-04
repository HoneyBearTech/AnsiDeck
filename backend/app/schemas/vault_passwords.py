from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class VaultPasswordCreate(BaseModel):
    """Either `password` (stored encrypted here) or a secret store reference."""

    name: str
    description: str | None = None
    password: str | None = None
    store_path: str | None = Field(None, max_length=400)
    store_key: str | None = Field(None, max_length=100)
    project_id: int | None = None

    @field_validator("password")
    @classmethod
    def _non_empty(cls, v: str | None) -> str | None:
        if v is not None and not v:
            raise ValueError("password must not be empty")
        return v

    @model_validator(mode="after")
    def _one_source(self) -> "VaultPasswordCreate":
        if (self.password is None) == (self.store_path is None):
            raise ValueError("give either password or store_path")
        if self.store_path is not None and not self.store_key:
            self.store_key = "password"
        return self


class VaultPasswordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int
    created_at: datetime
    store: Literal["ansideck", "external"] = "ansideck"
    store_path: str | None = None
    store_key: str | None = None
    store_location: str | None = None
