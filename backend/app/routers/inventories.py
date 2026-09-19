from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Inventory, InventoryGroup, InventoryHost, User
from app.permissions import SAFE_METHODS, Permission, Scope, guard
from app.schemas.inventories import (
    GroupCreate,
    GroupOut,
    GroupUpdate,
    HostCreate,
    HostOut,
    HostUpdate,
    InventoryCreate,
    InventoryDetail,
    InventorySummary,
    InventoryUpdate,
)
from app.scoping import get_scoped, readable_project_ids, resolve_write_project

_guard = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


def _get_inventory_or_404(
    db: Session, user: User, request: Request, inventory_id: int
) -> Inventory:
    """Every by-id route here (including groups and hosts) resolves the inventory
    first, so a group/host can only be reached through a project the caller is in."""
    permission = (
        Permission.CONTENT_READ if request.method in SAFE_METHODS else Permission.CONTENT_WRITE
    )
    return get_scoped(db, user, request, Inventory, inventory_id, permission, "Inventory not found")


def _get_group_or_404(db: Session, inventory_id: int, group_id: int) -> InventoryGroup:
    group = db.get(InventoryGroup, group_id)
    if group is None or group.inventory_id != inventory_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    return group


def _get_host_or_404(db: Session, inventory_id: int, host_id: int) -> InventoryHost:
    host = db.get(InventoryHost, host_id)
    if host is None or host.inventory_id != inventory_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host not found")
    return host


def _resolve_groups(db: Session, inventory_id: int, group_ids: list[int]) -> list[InventoryGroup]:
    if not group_ids:
        return []
    groups = db.query(InventoryGroup).filter(InventoryGroup.id.in_(group_ids)).all()
    if len(groups) != len(set(group_ids)) or any(g.inventory_id != inventory_id for g in groups):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "One or more group_ids are invalid for this inventory"
        )
    return groups


def _to_host_out(host: InventoryHost) -> HostOut:
    return HostOut(
        id=host.id,
        hostname=host.hostname,
        vars=host.vars,
        group_ids=[g.id for g in host.groups],
    )


def _to_inventory_detail(inventory: Inventory) -> InventoryDetail:
    return InventoryDetail(
        id=inventory.id,
        name=inventory.name,
        description=inventory.description,
        project_id=inventory.project_id,
        groups=list(inventory.groups),
        hosts=[_to_host_out(h) for h in inventory.hosts],
    )


@router.get("", response_model=list[InventorySummary])
def list_inventories(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[Inventory]:
    ids = readable_project_ids(db, user, request, Permission.CONTENT_READ, project_id)
    query = db.query(Inventory)
    if ids is not None:
        query = query.filter(Inventory.project_id.in_(ids))
    return query.order_by(Inventory.name).all()


@router.post("", response_model=InventoryDetail, status_code=status.HTTP_201_CREATED)
def create_inventory(
    payload: InventoryCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryDetail:
    project_id = resolve_write_project(
        db, user, request, payload.project_id, Permission.CONTENT_WRITE
    )
    inventory = Inventory(name=payload.name, description=payload.description, project_id=project_id)
    db.add(inventory)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Inventory name already exists") from exc
    db.refresh(inventory)
    return _to_inventory_detail(inventory)


@router.get("/{inventory_id}", response_model=InventoryDetail)
def get_inventory(
    inventory_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryDetail:
    return _to_inventory_detail(_get_inventory_or_404(db, user, request, inventory_id))


@router.put("/{inventory_id}", response_model=InventoryDetail)
def update_inventory(
    inventory_id: int,
    payload: InventoryUpdate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryDetail:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    if payload.name is not None:
        inventory.name = payload.name
    if payload.description is not None:
        inventory.description = payload.description
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Inventory name already exists") from exc
    db.refresh(inventory)
    return _to_inventory_detail(inventory)


@router.delete("/{inventory_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_inventory(
    inventory_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    db.delete(inventory)
    db.commit()


@router.post(
    "/{inventory_id}/groups",
    response_model=GroupOut,
    status_code=status.HTTP_201_CREATED,
)
def create_group(
    inventory_id: int,
    payload: GroupCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryGroup:
    _get_inventory_or_404(db, user, request, inventory_id)
    group = InventoryGroup(inventory_id=inventory_id, name=payload.name)
    db.add(group)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Group name already exists in this inventory"
        ) from exc
    db.refresh(group)
    return group


@router.put("/{inventory_id}/groups/{group_id}", response_model=GroupOut)
def update_group(
    inventory_id: int,
    group_id: int,
    payload: GroupUpdate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryGroup:
    _get_inventory_or_404(db, user, request, inventory_id)
    group = _get_group_or_404(db, inventory_id, group_id)
    group.name = payload.name
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Group name already exists in this inventory"
        ) from exc
    db.refresh(group)
    return group


@router.delete("/{inventory_id}/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    inventory_id: int,
    group_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    _get_inventory_or_404(db, user, request, inventory_id)
    group = _get_group_or_404(db, inventory_id, group_id)
    db.delete(group)
    db.commit()


@router.post("/{inventory_id}/hosts", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def create_host(
    inventory_id: int,
    payload: HostCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> HostOut:
    _get_inventory_or_404(db, user, request, inventory_id)
    groups = _resolve_groups(db, inventory_id, payload.group_ids)
    host = InventoryHost(
        inventory_id=inventory_id, hostname=payload.hostname, vars=payload.vars, groups=groups
    )
    db.add(host)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Host already exists in this inventory"
        ) from exc
    db.refresh(host)
    return _to_host_out(host)


@router.put("/{inventory_id}/hosts/{host_id}", response_model=HostOut)
def update_host(
    inventory_id: int,
    host_id: int,
    payload: HostUpdate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> HostOut:
    _get_inventory_or_404(db, user, request, inventory_id)
    host = _get_host_or_404(db, inventory_id, host_id)
    if payload.hostname is not None:
        host.hostname = payload.hostname
    if payload.vars is not None:
        host.vars = payload.vars
    if payload.group_ids is not None:
        host.groups = _resolve_groups(db, inventory_id, payload.group_ids)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Host already exists in this inventory"
        ) from exc
    db.refresh(host)
    return _to_host_out(host)


@router.delete("/{inventory_id}/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    inventory_id: int,
    host_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    _get_inventory_or_404(db, user, request, inventory_id)
    host = _get_host_or_404(db, inventory_id, host_id)
    db.delete(host)
    db.commit()
