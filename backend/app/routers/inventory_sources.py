"""An inventory's dynamic sources (Phase 4G), its refreshes and what they found.

Project admins (sources:manage) add, change and remove sources, whose configs run as code in
a worker; anyone who may change content (content:write) can refresh; anyone who can see the
inventory sees the sources, their status and the hosts and groups they found (secret-looking
vars masked).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.inventory_render import merge, static_data, target_hosts
from app.inventory_sources import SourceError, check_config, enqueue_refresh, has_sources
from app.models import (
    Credential,
    Inventory,
    InventoryRefresh,
    InventorySnapshot,
    InventorySource,
    RunStatus,
    User,
)
from app.notify import notifier
from app.permissions import Permission, Scope, guard
from app.queue import QUEUE_TOPIC
from app.schemas.inventory_sources import (
    GraphGroup,
    InventoryGraph,
    MergedHost,
    MergedHosts,
    RefreshOut,
    RefreshSettings,
    SnapshotGroup,
    SnapshotOut,
    SourceCreate,
    SourceOut,
    SourceUpdate,
    TargetGroup,
    Targets,
)
from app.scoping import get_scoped
from app.scrub import mask_secret_keys

router = APIRouter()

# The guard is the coarse "somewhere" check; each handler checks the inventory's project.
_manage = guard(Permission.CONTENT_READ, Permission.SOURCES_MANAGE, scope=Scope.PROJECT)
_refresh = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)

MAX_SOURCES = 20
PAGE_SIZE = 100


def _inventory(
    db: Session, user: User, request: Request, inventory_id: int, permission: Permission
) -> Inventory:
    return get_scoped(db, user, request, Inventory, inventory_id, permission, "Inventory not found")


def _source(db: Session, inventory: Inventory, source_id: int) -> InventorySource:
    source = db.get(InventorySource, source_id)
    if source is None or source.inventory_id != inventory.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source not found")
    return source


def _out(db: Session, source: InventorySource) -> dict:
    credential = db.get(Credential, source.credential_id) if source.credential_id else None
    return {
        **SourceOut.model_validate(source).model_dump(),
        "credential_name": credential.name if credential else None,
    }


def _check_credential(db: Session, inventory: Inventory, credential_id: int | None) -> None:
    if credential_id is None:
        return
    credential = db.get(Credential, credential_id)
    if credential is None or credential.project_id != inventory.project_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pick a credential of this project")
    if credential.kind != "env":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "A source's credential must be environment variables"
        )


def _plugin(config: str) -> str:
    try:
        return check_config(config)
    except SourceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Config: {exc}") from None


def _audit(db, action: str, user: User, request: Request, inventory: Inventory, **detail):
    audit.record(
        db,
        action,
        actor=user,
        target_type="inventory",
        target_id=inventory.id,
        target_name=inventory.name,
        ip=client_ip(request),
        project_id=inventory.project_id,
        detail=detail or None,
    )


def _sources_changed(db: Session, inventory: Inventory, user: User) -> None:
    """Refresh with the new sources; without any, the inventory has no snapshot."""
    if enqueue_refresh(db, inventory, "sources_changed", user.username) is not None:
        db.commit()
        notifier.notify(QUEUE_TOPIC)
    elif not has_sources(db, inventory.id) and inventory.current_snapshot_id is not None:
        inventory.current_snapshot_id = None
        db.commit()


@router.get("/sources", response_model=list[SourceOut])
def list_sources(
    inventory_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[dict]:
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    return [_out(db, source) for source in inventory.sources]


@router.post("/sources", response_model=SourceOut, status_code=status.HTTP_201_CREATED)
def create_source(
    inventory_id: int,
    payload: SourceCreate,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    if len(inventory.sources) >= MAX_SOURCES:
        raise HTTPException(status.HTTP_409_CONFLICT, "This inventory has too many sources")
    plugin = _plugin(payload.config)
    _check_credential(db, inventory, payload.credential_id)
    source = InventorySource(
        inventory_id=inventory.id,
        name=payload.name.strip(),
        plugin=plugin,
        config=payload.config,
        credential_id=payload.credential_id,
        enabled=payload.enabled,
        position=payload.position,
        created_by=user.username,
    )
    db.add(source)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A source with that name already exists"
        ) from exc
    db.refresh(source)
    _audit(
        db, "inventory_source.create", user, request, inventory, source=source.name, plugin=plugin
    )
    _sources_changed(db, inventory, user)
    return _out(db, source)


@router.patch("/sources/{source_id}", response_model=SourceOut)
def update_source(
    inventory_id: int,
    source_id: int,
    payload: SourceUpdate,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    source = _source(db, inventory, source_id)
    values = payload.model_dump(exclude_unset=True)
    if "config" in values:
        source.plugin = _plugin(values["config"])
        source.config = values["config"]
    if "credential_id" in values:
        _check_credential(db, inventory, values["credential_id"])
        source.credential_id = values["credential_id"]
    for key in ("enabled", "position"):
        if values.get(key) is not None:
            setattr(source, key, values[key])
    if values.get("name"):
        source.name = values["name"].strip()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A source with that name already exists"
        ) from exc
    db.refresh(source)
    _audit(
        db, "inventory_source.update", user, request, inventory,
        source=source.name, plugin=source.plugin, changed=sorted(values),
    )  # fmt: skip
    _sources_changed(db, inventory, user)
    return _out(db, source)


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(
    inventory_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> None:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    source = _source(db, inventory, source_id)
    name, plugin = source.name, source.plugin
    db.delete(source)
    db.commit()
    _audit(db, "inventory_source.delete", user, request, inventory, source=name, plugin=plugin)
    _sources_changed(db, inventory, user)


@router.put("/refresh-settings", response_model=Targets)
def update_refresh_settings(
    inventory_id: int,
    payload: RefreshSettings,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> Targets:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    inventory.refresh_interval_seconds = payload.refresh_interval_seconds
    db.commit()
    _audit(
        db, "inventory.refresh_settings", user, request, inventory,
        refresh_interval_seconds=payload.refresh_interval_seconds,
    )  # fmt: skip
    return _targets(db, inventory)


@router.post("/refresh", response_model=RefreshOut | None, status_code=status.HTTP_202_ACCEPTED)
def request_refresh(
    inventory_id: int,
    request: Request,
    user: User = Depends(_refresh),
    db: Session = Depends(get_db),
) -> InventoryRefresh | None:
    """Queues a refresh now (merged with one already queued)."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_WRITE)
    if not has_sources(db, inventory.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "This inventory has no enabled sources")
    enqueue_refresh(db, inventory, "manual", user.username)
    db.commit()
    notifier.notify(QUEUE_TOPIC)
    _audit(db, "inventory.refresh_requested", user, request, inventory)
    return db.scalars(
        select(InventoryRefresh)
        .where(
            InventoryRefresh.inventory_id == inventory.id,
            InventoryRefresh.status == RunStatus.QUEUED.value,
        )
        .limit(1)
    ).first()


@router.get("/refreshes", response_model=list[RefreshOut])
def list_refreshes(
    inventory_id: int,
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[InventoryRefresh]:
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    return list(
        db.scalars(
            select(InventoryRefresh)
            .where(InventoryRefresh.inventory_id == inventory.id)
            .order_by(InventoryRefresh.id.desc())
            .limit(limit)
        )
    )


def _current(db: Session, inventory: Inventory) -> InventorySnapshot | None:
    if inventory.current_snapshot_id is None or not has_sources(db, inventory.id):
        return None
    return db.get(InventorySnapshot, inventory.current_snapshot_id)


@router.get("/snapshot", response_model=SnapshotOut | None)
def get_snapshot(
    inventory_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> SnapshotOut | None:
    """The sources' current snapshot: its groups (vars masked) and warnings."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    snapshot = _current(db, inventory)
    if snapshot is None:
        return None
    data = snapshot.data
    return SnapshotOut(
        id=snapshot.id,
        created_at=snapshot.created_at,
        refresh_id=snapshot.refresh_id,
        host_count=snapshot.host_count,
        group_count=snapshot.group_count,
        warnings=snapshot.warnings or [],
        sources=snapshot.sources or [],
        vars=mask_secret_keys(data.get("vars") or {}),
        groups=[
            SnapshotGroup(
                name=name,
                hosts=len(group["hosts"]),
                children=group["children"],
                vars=mask_secret_keys(group["vars"]),
            )
            for name, group in sorted(data["groups"].items())
        ],
    )


def _graph(db: Session, inventory: Inventory) -> tuple[dict, dict, dict | None]:
    static = static_data(inventory)
    snapshot = _current(db, inventory)
    data = snapshot.data if snapshot is not None else None
    return merge(static, data), static, data


@router.get("/hosts", response_model=MergedHosts)
def merged_hosts(
    inventory_id: int,
    request: Request,
    q: str | None = Query(None, max_length=255),
    group: str | None = Query(None, max_length=255),
    page: int = Query(1, ge=1),
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> MergedHosts:
    """Every host a run would see (static and from sources), with where it came from and
    which source vars the inventory's own vars replace. Secret-looking vars are masked.
    `group` keeps the hosts in that group or any group below it (what `--limit` selects)."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    graph, static, snapshot = _graph(db, inventory)
    pool = graph["hosts"]
    if group is not None:
        try:
            pool = target_hosts(graph, group)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found") from None
    names = sorted(h for h in pool if not q or q.lower() in h.lower())
    groups_of: dict[str, list[str]] = {}
    for group_name, group in graph["groups"].items():
        for host in group["hosts"]:
            groups_of.setdefault(host, []).append(group_name)
    source_hosts = (snapshot or {}).get("hosts", {})
    hosts = []
    for name in names[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]:
        # The inventory's own hosts are fed to the plugins, so they come back in the snapshot
        # with their own vars: a source only counts where it added or changed something.
        own = static["hosts"].get(name)
        found = source_hosts.get(name) or {}
        added = [k for k in found if own is None or k not in own]
        overridden = sorted(k for k in found if own is not None and k in own and own[k] != found[k])
        if own is None:  # noqa: SIM108 - a nested conditional expression reads worse
            origin = "source"
        else:
            origin = "both" if added or overridden else "static"
        hosts.append(
            MergedHost(
                name=name,
                origin=origin,
                groups=sorted(groups_of.get(name, [])),
                vars=mask_secret_keys({str(k): v for k, v in graph["hosts"][name].items()}),
                overridden=overridden,
            )
        )
    return MergedHosts(total=len(names), hosts=hosts)


def _origin(name: str, static: dict, source_groups: set[str]) -> str:
    """Where a group comes from: the inventory's own groups, its sources', or both."""
    if name in static["groups"]:
        return "both" if name in source_groups else "static"
    return "source"


def _targets(db: Session, inventory: Inventory) -> Targets:
    graph, static, snapshot = _graph(db, inventory)
    source_groups = set((snapshot or {}).get("groups", {}))
    last = db.scalars(
        select(InventoryRefresh)
        .where(InventoryRefresh.inventory_id == inventory.id)
        .order_by(InventoryRefresh.id.desc())
        .limit(1)
    ).first()
    current = _current(db, inventory)
    return Targets(
        has_sources=has_sources(db, inventory.id),
        hosts=len(graph["hosts"]),
        groups=[
            TargetGroup(
                name=name,
                hosts=len(group["hosts"]),
                origin=_origin(name, static, source_groups),
            )
            for name, group in sorted(graph["groups"].items())
        ],
        snapshot_id=current.id if current else None,
        snapshot_at=current.created_at if current else None,
        last_refresh=RefreshOut.model_validate(last) if last else None,
        refresh_interval_seconds=inventory.refresh_interval_seconds,
    )


@router.get("/targets", response_model=Targets)
def targets(
    inventory_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> Targets:
    """The groups a run can target (the inventory's own and its sources'), for the run page."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    return _targets(db, inventory)


@router.get("/graph", response_model=InventoryGraph)
def graph(
    inventory_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> InventoryGraph:
    """How the groups nest (the inventory's own and its sources'), with each group's direct
    host count, for the group graph. Names and counts only: no vars."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    merged, static, snapshot = _graph(db, inventory)
    groups = merged["groups"]
    source_groups = set((snapshot or {}).get("groups", {}))
    grouped = {host for group in groups.values() for host in group["hosts"]}
    current = _current(db, inventory)
    return InventoryGraph(
        name=inventory.name,
        hosts=len(merged["hosts"]),
        ungrouped=len(merged["hosts"].keys() - grouped),
        groups=[
            GraphGroup(
                name=name,
                hosts=len(group["hosts"]),
                children=[child for child in group["children"] if child in groups],
                origin=_origin(name, static, source_groups),
            )
            for name, group in sorted(groups.items())
        ],
        snapshot_id=current.id if current else None,
        snapshot_at=current.created_at if current else None,
    )
