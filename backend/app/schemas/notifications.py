from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Kind = Literal["webhook", "discord", "slack", "teams", "email", "pushbullet", "pushover"]


class _Secrets(BaseModel):
    """Write-only: never returned. On update, an omitted (null) field keeps what is stored."""

    url: str | None = Field(None, max_length=2000)
    secret: str | None = Field(None, max_length=500)  # webhook signing secret; "" removes it
    token: str | None = Field(None, max_length=200)  # Pushbullet / Pushover
    user_key: str | None = Field(None, max_length=200)  # Pushover
    recipients: list[str] | None = Field(None, max_length=20)  # email


class ChannelCreate(_Secrets):
    name: str = Field(min_length=1, max_length=100)
    kind: Kind
    events: list[str] = Field(min_length=1, max_length=20)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a name is required")
        return v


class ChannelUpdate(_Secrets):
    name: str | None = Field(None, min_length=1, max_length=100)
    events: list[str] | None = Field(None, min_length=1, max_length=20)
    enabled: bool | None = None


class LastDelivery(BaseModel):
    status: str
    event: str
    created_at: datetime
    error: str | None


class ChannelOut(BaseModel):
    id: int
    project_id: int | None
    name: str
    kind: str
    # Where it goes, safe to show: scheme://host/…last 4 for webhooks, the addresses for
    # email, the service name for push. Never the URL's path or a token.
    target: str
    recipients: list[str] | None = None
    has_secret: bool = False
    events: list[str]
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_delivery: LastDelivery | None = None


class DeliveryOut(BaseModel):
    id: int
    event: str
    title: str
    status: str
    attempts: int
    last_status_code: int | None
    last_error: str | None
    created_at: datetime
    next_attempt_at: datetime | None
    sent_at: datetime | None


class TestResult(BaseModel):
    ok: bool
    status_code: int | None
    error: str | None


class EventOut(BaseModel):
    name: str
    label: str
    description: str
    project: bool  # available to project channels (global channels get every event)
    group: str  # Runs, Operations, Security


class CatalogOut(BaseModel):
    events: list[EventOut]
    kinds: list[str]
    email_available: bool  # SMTP_HOST is set
