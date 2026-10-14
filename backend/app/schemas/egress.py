from typing import Literal

from pydantic import BaseModel, Field


class EgressExtra(BaseModel):
    """An address, a network (CIDR) or a host name runs may also reach; `ports` like "443",
    "80,443" or "8000-8100" (tcp and udp), empty or None for any port."""

    target: str = Field(max_length=255)
    ports: str | None = Field(None, max_length=200)
    note: str | None = Field(None, max_length=200)


class EgressExtraOut(BaseModel):
    target: str
    ports: list[tuple[int, int]] | None
    note: str | None = None


class EgressHost(BaseModel):
    host: str
    connection: str
    # ok: its address is allowed; local: no network; indirect: through a jump host or a
    # proxy; unknown: its address isn't known before the run, so restricted runs are refused
    status: Literal["ok", "local", "indirect", "unknown"]
    address: str | None = None
    jump_host: str | None = None  # "host:port"
    reason: str | None = None


class EgressSummary(BaseModel):
    hosts: int
    ok: int
    local: int
    indirect: int
    unknown: int


class EgressOut(BaseModel):
    restricted: bool
    extras: list[EgressExtraOut]
    hosts: list[EgressHost]
    total: int  # hosts matching the filter (one page of them is in `hosts`)
    summary: EgressSummary
    warnings: list[str]


class EgressModeIn(BaseModel):
    restricted: bool


class EgressExtrasIn(BaseModel):
    extras: list[EgressExtra] = Field(max_length=200)
