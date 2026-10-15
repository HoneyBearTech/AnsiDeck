from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MIN_INTERVAL_SECONDS = 300
MAX_INTERVAL_SECONDS = 7 * 24 * 3600


def _check_interval(value: int | None) -> int | None:
    """None (inherit), 0 (only when something changes), or 5 minutes to a week."""
    if (
        value is not None
        and value != 0
        and not MIN_INTERVAL_SECONDS <= value <= MAX_INTERVAL_SECONDS
    ):
        raise ValueError(
            f"use 0 (only when something changes) or {MIN_INTERVAL_SECONDS} to "
            f"{MAX_INTERVAL_SECONDS} seconds"
        )
    return value


class SourceCreate(BaseModel):
    """kind "plugin": `config`, an inventory plugin's config (and an optional env credential).
    kind "git_file": `git_source_id` (a git source of the project) and `path`, an inventory file
    or directory in it. kind "git_script": `git_source_id` and `path`, an executable inventory
    script in it (run with its directory), and an optional env credential."""

    name: str = Field(min_length=1, max_length=100)
    kind: Literal["plugin", "git_file", "git_script"] = "plugin"
    config: str | None = Field(None, min_length=1, max_length=64 * 1024)
    git_source_id: int | None = None
    path: str | None = Field(None, min_length=1, max_length=1024)
    credential_id: int | None = None
    enabled: bool = True
    position: int = Field(0, ge=0, le=1000)
    # None: the inventory's refresh interval; 0: only when something changes.
    refresh_interval_seconds: int | None = None

    _interval = field_validator("refresh_interval_seconds")(_check_interval)

    @model_validator(mode="after")
    def _fields_of_its_kind(self) -> "SourceCreate":
        if self.kind == "plugin":
            if self.config is None or self.git_source_id is not None or self.path is not None:
                raise ValueError("a plugin source holds config (and no git_source_id or path)")
        elif self.git_source_id is None or self.path is None or self.config is not None:
            raise ValueError("a git source's file or script needs git_source_id and path only")
        elif self.kind == "git_file" and self.credential_id is not None:
            raise ValueError("an inventory file reads no credential (a script can)")
        return self


class SourceUpdate(BaseModel):
    """Fields of the source's own kind only."""

    name: str | None = Field(None, min_length=1, max_length=100)
    config: str | None = Field(None, min_length=1, max_length=64 * 1024)
    git_source_id: int | None = None
    path: str | None = Field(None, min_length=1, max_length=1024)
    credential_id: int | None = None
    enabled: bool | None = None
    position: int | None = Field(None, ge=0, le=1000)
    # Sent as null: the inventory's refresh interval again.
    refresh_interval_seconds: int | None = None

    _interval = field_validator("refresh_interval_seconds")(_check_interval)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    inventory_id: int
    name: str
    kind: str = "plugin"
    plugin: str
    config: str | None
    # A git file source: its git source, the path in it, and since when the commit lacks it.
    git_source_id: int | None = None
    git_source_name: str | None = None
    path: str | None = None
    missing_at: datetime | None = None
    credential_id: int | None
    credential_name: str | None = None
    enabled: bool
    position: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    refresh_interval_seconds: int | None = None
    # What applies (its own or the inventory's; 0: only when something changes; constructed
    # sources: 0, they are re-applied in every refresh), and when a schedule runs it next.
    effective_interval_seconds: int = 0
    last_queued_at: datetime | None = None
    next_refresh_at: datetime | None = None
    # Why it failed the last time it ran (None: it worked) and when that was; what its last good
    # output held, which refreshes keep using until it works again.
    last_error: str | None = None
    last_finished_at: datetime | None = None
    output_refreshed_at: datetime | None = None
    output_host_count: int | None = None
    output_group_count: int | None = None
    output_warnings: list[str] = []
    # A git file source: the commit its last good output was read from.
    output_git_commit: str | None = None


class RefreshSettings(BaseModel):
    """0: refreshed only on demand (and when sources or the inventory's hosts change)."""

    refresh_interval_seconds: int | None = Field(None, ge=0, le=MAX_INTERVAL_SECONDS)
    # Runs refresh the sources first unless whoever starts one unticks it. None keeps it.
    refresh_before_run: bool | None = None

    @field_validator("refresh_interval_seconds")
    @classmethod
    def _sensible(cls, value: int | None) -> int | None:
        if value is not None and 0 < value < MIN_INTERVAL_SECONDS:
            raise ValueError(f"refresh at most every {MIN_INTERVAL_SECONDS} seconds")
        return value


class RefreshSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_id: int | None
    name: str
    plugin: str
    ran: bool
    # None while it runs; success | failed | stale (it was edited meanwhile: discarded).
    status: str | None
    error: str | None
    host_count: int | None


class RefreshOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    trigger: str
    requested_by: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    worker_id: str | None
    error: str | None
    snapshot_id: int | None
    # The sources it runs (None: all; []: none, it only combines what they found last).
    scope: list[int] | None = None
    # What each source did (the constructed ones don't run on their own: ran false).
    source_results: list[RefreshSourceOut] = []


class SnapshotGroup(BaseModel):
    name: str
    hosts: int
    children: list[str]
    vars: dict[str, Any]


class SnapshotOut(BaseModel):
    id: int
    created_at: datetime
    refresh_id: int | None
    host_count: int
    group_count: int
    warnings: list[str]
    sources: list[dict]
    vars: dict[str, Any]
    groups: list[SnapshotGroup]


class MergedHost(BaseModel):
    name: str
    # "static": the inventory's own; "source": from a source; "both": static vars override.
    origin: str
    groups: list[str]
    vars: dict[str, Any]
    # Keys whose source value the inventory's own vars replace.
    overridden: list[str]


class MergedHosts(BaseModel):
    total: int
    hosts: list[MergedHost]


class TargetGroup(BaseModel):
    name: str
    hosts: int
    origin: str  # static, source or both


class GraphGroup(BaseModel):
    name: str
    hosts: int  # direct members only; the hosts below it come from /hosts?group=
    children: list[str]
    origin: str  # static, source or both


class InventoryGraph(BaseModel):
    """How the inventory's groups nest: names, edges and counts only, never vars."""

    name: str  # the inventory's, so the graph page needs nothing else (the detail has vars)
    hosts: int
    ungrouped: int  # hosts in no group
    groups: list[GraphGroup]
    snapshot_id: int | None
    snapshot_at: datetime | None


class Targets(BaseModel):
    """What a run of this inventory can target, and how fresh its sources' data is."""

    has_sources: bool
    hosts: int
    groups: list[TargetGroup]
    snapshot_id: int | None
    snapshot_at: datetime | None
    last_refresh: RefreshOut | None
    refresh_interval_seconds: int
    refresh_before_run: bool = False
