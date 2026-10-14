from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Mode = Literal["off", "accept_new", "strict"]


class HostKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str  # `host` or `[host]:port`, as ssh looks it up
    key_type: str
    fingerprint: str
    source: str  # scan, paste, learned
    confirmed: bool
    run_id: int | None
    created_by: str
    created_at: datetime
    confirmed_by: str | None
    confirmed_at: datetime | None
    # The inventory's hosts that connect to this name (first 20); none: no host uses it now
    # (a jump host, or a host that has moved).
    hosts: list[str] = []


class HostKeyHost(BaseModel):
    host: str
    name: str | None  # None: not known before the run (templated), or not ssh
    connection: str
    # trusted: has a confirmed key; learned: unconfirmed keys only; missing: no key;
    # unknown: its address isn't known in advance; not_checked: doesn't connect with ssh
    status: Literal["trusted", "learned", "missing", "unknown", "not_checked"]
    reason: str | None = None


class HostKeySummary(BaseModel):
    hosts: int
    trusted: int
    learned: int
    missing: int
    unknown: int
    not_checked: int


class HostKeysOut(BaseModel):
    mode: Mode
    keys: list[HostKeyOut]
    hosts: list[HostKeyHost]  # one page, filtered by q
    total: int  # hosts matching q
    summary: HostKeySummary  # all hosts


class ModeIn(BaseModel):
    mode: Mode


class PasteIn(BaseModel):
    known_hosts: str = Field(min_length=1, max_length=256 * 1024)
    # Only show what would change.
    dry_run: bool = False


class PastedKey(BaseModel):
    name: str
    key_type: str
    fingerprint: str
    # new, replace (another key of that type was trusted), confirm (was learned), same
    change: Literal["new", "replace", "confirm", "same"]
    previous: str | None = None  # the fingerprint it replaces
    hosts: list[str] = []


class PasteOut(BaseModel):
    keys: list[PastedKey]
    warnings: list[str]


class ConfirmIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=2000)


class ScanIn(BaseModel):
    # The inventory hosts to scan (all when left out), and extra names such as jump hosts
    # (`host` or `[host]:port`).
    hosts: list[str] | None = Field(None, max_length=5000)
    extra: list[str] = Field([], max_length=20)


class ScannedKey(BaseModel):
    name: str
    key_type: str
    fingerprint: str
    hosts: list[str] = []
    # trusted: the same key is trusted; learned: the same key was learned (trusting it confirms
    # it); new: no key of this type is trusted for the name; changed: a different one is.
    state: Literal["trusted", "learned", "new", "changed"]
    previous: str | None = None  # the trusted key's fingerprint, when changed


class ScanOut(BaseModel):
    id: int
    status: str
    wait_reason: str | None = None
    error: str | None = None
    requested_by: str
    queued_at: datetime
    finished_at: datetime | None
    targets: int
    keys: list[ScannedKey] = []
    # Targets that presented no key (unreachable, or not ssh).
    silent: list[str] = []


class TrustKey(BaseModel):
    name: str = Field(max_length=300)
    key_type: str = Field(max_length=64)


class TrustIn(BaseModel):
    scan_id: int
    keys: list[TrustKey] = Field(min_length=1, max_length=1500)
