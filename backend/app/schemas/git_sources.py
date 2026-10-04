from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

AuthKind = Literal["none", "ssh_key", "https_token"]


def _interval(value: int | None) -> int | None:
    if value is not None and 0 < value < 60:
        raise ValueError("sync at most once a minute (or 0 for manual syncs only)")
    return value


class GitSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=500)
    branch: str = Field("main", min_length=1, max_length=255)
    subdir: str | None = Field(None, max_length=500)
    web_url: str | None = Field(None, max_length=500)
    playbook_globs: list[str] | None = Field(None, max_length=20)
    auth_kind: AuthKind = "none"
    credential_id: int | None = None
    https_username: str | None = Field(None, max_length=255)
    token: str | None = Field(None, min_length=1, max_length=4096)  # write-only
    auto_sync_seconds: int = Field(300, ge=0, le=86_400)
    enabled: bool = True

    _check_interval = field_validator("auto_sync_seconds")(_interval)


class GitSourceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    url: str | None = Field(None, min_length=1, max_length=500)
    branch: str | None = Field(None, min_length=1, max_length=255)
    subdir: str | None = Field(None, max_length=500)
    web_url: str | None = Field(None, max_length=500)
    playbook_globs: list[str] | None = Field(None, max_length=20)
    auth_kind: AuthKind | None = None
    credential_id: int | None = None
    https_username: str | None = Field(None, max_length=255)
    token: str | None = Field(None, min_length=1, max_length=4096)
    auto_sync_seconds: int | None = Field(None, ge=0, le=86_400)
    enabled: bool | None = None

    _check_interval = field_validator("auto_sync_seconds")(_interval)


class HostKey(BaseModel):
    type: str
    fingerprint: str


class GitSourceOut(BaseModel):
    id: int
    project_id: int
    name: str
    url: str
    branch: str
    subdir: str | None
    web_url: str | None
    playbook_globs: list[str]
    auth_kind: AuthKind
    credential_id: int | None
    credential_name: str | None
    https_username: str | None
    has_token: bool
    host_keys: list[HostKey]  # trusted SSH host keys (fingerprints only)
    auto_sync_seconds: int
    enabled: bool
    commit: str | None
    commit_subject: str | None
    committed_at: datetime | None
    warnings: list[str]
    playbooks: int
    missing_playbooks: int
    sync_requested_at: datetime | None
    last_sync_started_at: datetime | None
    last_sync_finished_at: datetime | None
    last_sync_status: str | None
    last_sync_error: str | None
    created_by: str
    created_at: datetime


class SnapshotOut(BaseModel):
    commit: str
    commit_subject: str
    commit_author: str
    committed_at: datetime | None
    size_bytes: int
    file_count: int
    warnings: list[str]
    created_at: datetime
    superseded_at: datetime | None
    current: bool


class ScannedKey(BaseModel):
    type: str
    fingerprint: str
    trusted: bool


class TestResult(BaseModel):
    ok: bool
    error: str | None = None
    default_branch: str | None = None
    branch_exists: bool | None = None
    host_keys: list[ScannedKey] = []  # ssh: what the server presented
    host_key_trusted: bool | None = None


class TrustHostKey(BaseModel):
    """Trust the scanned key with this fingerprint, or pasted known_hosts lines."""

    fingerprint: str | None = Field(None, max_length=100)
    known_hosts: str | None = Field(None, max_length=16_384)
