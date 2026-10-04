from pydantic import BaseModel


class SecretStoreInfo(BaseModel):
    enabled: bool
    label: str
    base_path: str | None  # e.g. secret/ansideck/7/: every reference of the project is below
    path_rules: str


class SecretStoreStatus(BaseModel):
    """The last probe (every minute while a store is configured)."""

    enabled: bool
    label: str
    url: str | None = None
    ok: bool | None = None
    reachable: bool | None = None
    sealed: bool | None = None
    version: str | None = None
    token_ttl: int | None = None  # seconds
    error_kind: str | None = None
    error: str | None = None
    checked_at: float | None = None  # unix time
    last_ok_at: float | None = None
