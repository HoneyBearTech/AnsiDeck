from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.permissions import Role


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=500)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=500)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    created_at: datetime


class ProjectListItem(ProjectOut):
    # The caller's role here ("admin" for a global admin), for UI display.
    my_role: str | None


class MemberOut(BaseModel):
    user_id: int
    username: str
    is_active: bool
    role: str


class MemberUpsert(BaseModel):
    role: Role


class MemberAdd(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    role: Role
