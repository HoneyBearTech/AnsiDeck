from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    actor_username: str | None
    project_id: int | None
    action: str
    target_type: str | None
    target_id: int | None
    target_name: str | None
    outcome: str
    ip: str | None
    detail: dict[str, Any] | None


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    total: int
