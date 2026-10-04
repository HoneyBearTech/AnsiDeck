from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CredentialCreate(BaseModel):
    """Either `private_key` (stored encrypted here) or a secret store reference: `store_path`
    under the project's own subtree and `store_key` in that secret."""

    name: str
    description: str | None = None
    private_key: str | None = None
    store_path: str | None = Field(None, max_length=400)
    store_key: str | None = Field(None, max_length=100)
    project_id: int | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "CredentialCreate":
        if (self.private_key is None) == (self.store_path is None):
            raise ValueError("give either private_key or store_path")
        if self.store_path is not None and not self.store_key:
            self.store_key = "private_key"
        return self


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int
    created_at: datetime
    # "ansideck": encrypted in AnsiDeck's database; "external": in the secret store.
    store: Literal["ansideck", "external"] = "ansideck"
    store_path: str | None = None
    store_key: str | None = None
    store_location: str | None = None


class SecretCheck(BaseModel):
    """Whether a stored secret can be read (never its value)."""

    ok: bool
    version: int | None = None
    error_kind: str | None = None
    error: str | None = None
