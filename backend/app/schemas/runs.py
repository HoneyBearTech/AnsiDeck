from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RunCreate(BaseModel):
    playbook_id: int
    inventory_id: int
    group_id: int | None = None
    credential_id: int
    become: bool = False


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    playbook_name: str
    inventory_name: str
    group_name: str | None
    credential_name: str
    become: bool
    status: str
    triggered_by: str
    return_code: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
