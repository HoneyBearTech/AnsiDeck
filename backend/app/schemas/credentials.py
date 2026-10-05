from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CredentialCreate(BaseModel):
    """kind "ssh": either `private_key` (stored encrypted here) or a secret store reference,
    `store_path` under the project's own subtree and `store_key` in that secret.
    kind "env": either `env` (named variables, stored encrypted here) or `store_path`, a
    secret whose every key becomes a variable."""

    name: str
    description: str | None = None
    kind: Literal["ssh", "env"] = "ssh"
    private_key: str | None = None
    env: dict[str, str] | None = None
    store_path: str | None = Field(None, max_length=400)
    store_key: str | None = Field(None, max_length=100)
    project_id: int | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "CredentialCreate":
        value = self.private_key if self.kind == "ssh" else self.env
        other = self.env if self.kind == "ssh" else self.private_key
        if other is not None:
            raise ValueError("an ssh credential holds private_key, an env credential env")
        if (value is None) == (self.store_path is None):
            field = "private_key" if self.kind == "ssh" else "env"
            raise ValueError(f"give either {field} or store_path")
        if self.kind == "env":
            if self.store_key is not None:
                raise ValueError("an env credential reads the whole secret: no store_key")
        elif self.store_path is not None and not self.store_key:
            self.store_key = "private_key"
        return self


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int
    created_at: datetime
    kind: Literal["ssh", "env"] = "ssh"
    # An env credential's variable names (never their values); None when they live in the
    # secret store (they are whatever keys the secret has).
    env_names: list[str] | None = None
    # "ansideck": encrypted in AnsiDeck's database; "external": in the secret store.
    store: Literal["ansideck", "external"] = "ansideck"
    store_path: str | None = None
    store_key: str | None = None
    store_location: str | None = None


class SecretCheck(BaseModel):
    """Whether a stored secret can be read (never its value)."""

    ok: bool
    version: int | None = None
    # An env credential in the secret store: the variable names it holds now.
    env_names: list[str] | None = None
    error_kind: str | None = None
    error: str | None = None
