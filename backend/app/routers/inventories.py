from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.inventory_render import group_problem, hostname_problem
from app.inventory_sources import enqueue_refresh
from app.models import Inventory, InventoryGroup, InventoryHost, User
from app.notify import notifier
from app.permissions import SAFE_METHODS, Permission, Scope, guard, project_permissions
from app.queue import QUEUE_TOPIC
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
from app.scrub import mask_for_display

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


def _to_host_out(host: InventoryHost, masked: bool = False) -> HostOut:
    return HostOut(
        id=host.id,
        hostname=host.hostname,
        vars=mask_for_display(host.vars or {}) if masked else host.vars,
        group_ids=[g.id for g in host.groups],
    )


def _to_inventory_detail(inventory: Inventory, masked: bool = False) -> InventoryDetail:
    return InventoryDetail(
        id=inventory.id,
        name=inventory.name,
        description=inventory.description,
        project_id=inventory.project_id,
        groups=list(inventory.groups),
        hosts=[_to_host_out(h, masked) for h in inventory.hosts],
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


# Variable *names* only, never values: host vars often hold secrets.
_MAX_AUDITED_NAMES = 50


def _names(keys) -> list[str]:
    return sorted(str(k) for k in keys)[:_MAX_AUDITED_NAMES]


def _changed_vars(before: dict | None, after: dict | None) -> list[str]:
    before, after = before or {}, after or {}
    return _names(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))


def _audit(
    db: Session,
    action: str,
    user: User,
    request: Request,
    inventory: dict,
    target: tuple[str, int, str] | None = None,
    **detail,
) -> None:
    """`inventory` and `target` (type, id, name) are taken before a delete: the rows'
    attributes are gone after its commit."""
    target_type, target_id, target_name = target or (
        "inventory",
        inventory["id"],
        inventory["name"],
    )
    if target is not None:
        detail = {"inventory": inventory["name"], **detail}
    audit.record(
        db,
        action,
        actor=user,
        target_type=target_type,
        target_id=target_id,
        target_name=target_name,
        ip=client_ip(request),
        project_id=inventory["project_id"],
        detail=detail or None,
    )


def _inv(inventory: Inventory) -> dict:
    return {"id": inventory.id, "name": inventory.name, "project_id": inventory.project_id}


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
    _audit(db, "inventory.create", user, request, _inv(inventory))
    return _to_inventory_detail(inventory)


@router.get("/{inventory_id}", response_model=InventoryDetail)
def get_inventory(
    inventory_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryDetail:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    # Editors need the real values (the Edit host dialog saves what it shows); readers who
    # can't edit (viewers, read-only API keys) get secret-looking values masked.
    can_edit = Permission.CONTENT_WRITE in project_permissions(db, user, inventory.project_id)
    return _to_inventory_detail(inventory, masked=not can_edit)


@router.put("/{inventory_id}", response_model=InventoryDetail)
def update_inventory(
    inventory_id: int,
    payload: InventoryUpdate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InventoryDetail:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    detail: dict = {}
    if payload.name is not None and payload.name != inventory.name:
        detail["renamed_from"] = inventory.name
        inventory.name = payload.name
    if payload.description is not None and payload.description != inventory.description:
        detail["description_changed"] = True
        inventory.description = payload.description
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Inventory name already exists") from exc
    db.refresh(inventory)
    if detail:
        _audit(db, "inventory.update", user, request, _inv(inventory), **detail)
    return _to_inventory_detail(inventory)


@router.delete("/{inventory_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_inventory(
    inventory_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    ref = _inv(inventory)
    hosts, groups = len(inventory.hosts), len(inventory.groups)
    db.delete(inventory)
    db.commit()
    _audit(db, "inventory.delete", user, request, ref, hosts=hosts, groups=groups)


def _static_changed(db: Session, inventory_id: int, user: User) -> None:
    """The inventory's own hosts or groups changed: its sources (constructed ones group them)
    are refreshed, one refresh for a burst of edits."""
    inventory = db.get(Inventory, inventory_id)
    if enqueue_refresh(db, inventory, "static_changed", user.username) is not None:
        db.commit()
        notifier.notify(QUEUE_TOPIC)


def _check_group_name(name: str) -> None:
    if problem := group_problem(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Group name {problem}")


def _check_hostname(name: str) -> None:
    if problem := hostname_problem(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Host name {problem}")


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
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    _check_group_name(payload.name)
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
    _audit(
        db,
        "inventory.group_create",
        user,
        request,
        _inv(inventory),
        ("inventory_group", group.id, group.name),
    )
    _static_changed(db, inventory_id, user)
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
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    group = _get_group_or_404(db, inventory_id, group_id)
    _check_group_name(payload.name)
    old_name = group.name
    group.name = payload.name
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Group name already exists in this inventory"
        ) from exc
    db.refresh(group)
    if group.name != old_name:
        target = ("inventory_group", group.id, group.name)
        _audit(
            db,
            "inventory.group_update",
            user,
            request,
            _inv(inventory),
            target,
            renamed_from=old_name,
        )
    _static_changed(db, inventory_id, user)
    return group


@router.delete("/{inventory_id}/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    inventory_id: int,
    group_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    group = _get_group_or_404(db, inventory_id, group_id)
    ref, target = _inv(inventory), ("inventory_group", group.id, group.name)
    db.delete(group)
    db.commit()
    _audit(db, "inventory.group_delete", user, request, ref, target)
    _static_changed(db, inventory_id, user)


@router.post("/{inventory_id}/hosts", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def create_host(
    inventory_id: int,
    payload: HostCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> HostOut:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    _check_hostname(payload.hostname)
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
    _audit(
        db,
        "inventory.host_create",
        user,
        request,
        _inv(inventory),
        ("inventory_host", host.id, host.hostname),
        vars=_names(host.vars or {}),
        groups=_names(g.name for g in host.groups),
    )
    _static_changed(db, inventory_id, user)
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
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    host = _get_host_or_404(db, inventory_id, host_id)
    detail: dict = {}
    if payload.hostname is not None:
        _check_hostname(payload.hostname)
        if payload.hostname != host.hostname:
            detail["renamed_from"] = host.hostname
        host.hostname = payload.hostname
    if payload.vars is not None:
        if changed := _changed_vars(host.vars, payload.vars):
            detail["vars_changed"] = changed
        host.vars = payload.vars
    if payload.group_ids is not None:
        before = _names(g.name for g in host.groups)
        host.groups = _resolve_groups(db, inventory_id, payload.group_ids)
        if (after := _names(g.name for g in host.groups)) != before:
            detail["groups"] = after
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Host already exists in this inventory"
        ) from exc
    db.refresh(host)
    if detail:
        target = ("inventory_host", host.id, host.hostname)
        _audit(db, "inventory.host_update", user, request, _inv(inventory), target, **detail)
    _static_changed(db, inventory_id, user)
    return _to_host_out(host)


@router.delete("/{inventory_id}/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    inventory_id: int,
    host_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    inventory = _get_inventory_or_404(db, user, request, inventory_id)
    host = _get_host_or_404(db, inventory_id, host_id)
    ref, target = _inv(inventory), ("inventory_host", host.id, host.hostname)
    db.delete(host)
    db.commit()
    _audit(db, "inventory.host_delete", user, request, ref, target)
    _static_changed(db, inventory_id, user)
