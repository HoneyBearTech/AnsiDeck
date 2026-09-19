from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PlaybookCreate(BaseModel):
    name: str
    content: str
    project_id: int | None = None


class PlaybookUpdate(BaseModel):
    name: str | None = None
    content: str | None = None


class PlaybookSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    project_id: int
    created_at: datetime
    updated_at: datetime


class PlaybookDetail(PlaybookSummary):
    content: str
