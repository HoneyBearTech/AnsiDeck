from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class ProjectAccess(BaseModel):
    id: int
    name: str
    role: str
    permissions: list[str]


class UserOut(BaseModel):
    username: str
    role: str
    # Union across the user's projects (everything for a global admin).
    permissions: list[str]
    projects: list[ProjectAccess]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)
