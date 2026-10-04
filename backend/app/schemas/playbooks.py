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
    # Synced from git (read-only): the source, the file's path in the repository, the
    # commit it is shown at, and when it disappeared upstream (it can't run then).
    source_id: int | None = None
    source_name: str | None = None
    repo_path: str | None = None
    commit: str | None = None
    missing_at: datetime | None = None


class PlaybookDetail(PlaybookSummary):
    content: str
