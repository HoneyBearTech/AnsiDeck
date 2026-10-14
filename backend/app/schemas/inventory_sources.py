from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MIN_INTERVAL_SECONDS = 300
MAX_INTERVAL_SECONDS = 7 * 24 * 3600


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    config: str = Field(min_length=1, max_length=64 * 1024)
    credential_id: int | None = None
    enabled: bool = True
    position: int = Field(0, ge=0, le=1000)


class SourceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    config: str | None = Field(None, min_length=1, max_length=64 * 1024)
    credential_id: int | None = None
    enabled: bool | None = None
    position: int | None = Field(None, ge=0, le=1000)


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    inventory_id: int
    name: str
    plugin: str
    config: str
    credential_id: int | None
    credential_name: str | None = None
    enabled: bool
    position: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    # Why it failed the last time it ran (None: it worked) and when that was; what its last good
    # output held, which refreshes keep using until it works again.
    last_error: str | None = None
    last_finished_at: datetime | None = None
    output_refreshed_at: datetime | None = None
    output_host_count: int | None = None
    output_group_count: int | None = None
    output_warnings: list[str] = []


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
