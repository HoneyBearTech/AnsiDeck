from pydantic import BaseModel, ConfigDict


class InventoryCreate(BaseModel):
    name: str
    description: str | None = None
    project_id: int | None = None


class InventoryUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class InventorySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    project_id: int


class GroupCreate(BaseModel):
    name: str


class GroupUpdate(BaseModel):
    name: str


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class HostCreate(BaseModel):
    hostname: str
    vars: dict = {}
    group_ids: list[int] = []


class HostUpdate(BaseModel):
    hostname: str | None = None
    vars: dict | None = None
    group_ids: list[int] | None = None


class HostOut(BaseModel):
    id: int
    hostname: str
    vars: dict
    group_ids: list[int]


class InventoryDetail(InventorySummary):
    groups: list[GroupOut]
    hosts: list[HostOut]
