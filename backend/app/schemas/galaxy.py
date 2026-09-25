from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RequirementsPayload(BaseModel):
    content: str


class InstallCreate(BaseModel):
    upgrade: bool = False


class InstallOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    status_reason: str | None
    triggered_by: str
    upgrade: bool
    return_code: int | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class InstallDetail(InstallOut):
    requirements_snapshot: str
    log: str


class InstalledItem(BaseModel):
    name: str
    version: str | None


class InstalledOut(BaseModel):
    collections: list[InstalledItem]
    roles: list[InstalledItem]
