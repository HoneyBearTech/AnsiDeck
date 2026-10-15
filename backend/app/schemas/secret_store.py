from datetime import datetime

from pydantic import BaseModel


class SecretStoreInfo(BaseModel):
    enabled: bool
    label: str
    base_path: str | None  # e.g. secret/ansideck/7/: every reference of the project is below
    path_rules: str
    # SSH engine mounts SSH certificate credentials may use (SECRETS_STORE_SSH_MOUNTS; empty:
    # that kind isn't offered), and what the project's role names start with ("ansideck-7-").
    ssh_mounts: list[str] = []
    ssh_role_prefix: str | None = None
    # Secrets stored in AnsiDeck can be moved into the store (SECRETS_STORE_ALLOW_MOVE).
    move_enabled: bool = False


class SecretStoreStatus(BaseModel):
    """The last probe (every minute while a store is configured; every 15 s while it is down)."""

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
    # How long runs and refreshes that need it wait while it is down (0: they fail at once),
    # and the current outage (app.store_outage): its error kind and since when.
    wait_minutes: int = 0
    outage_kind: str | None = None
    outage_since: datetime | None = None
