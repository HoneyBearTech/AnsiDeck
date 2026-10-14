"""An inventory's dynamic sources (Phase 4G), its refreshes and what they found.

Project admins (sources:manage) add, change and remove sources, whose configs run as code in
a worker; anyone who may change content (content:write) can refresh; anyone who can see the
inventory sees the sources, their status and the hosts and groups they found (secret-looking
vars masked).
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.inventory_files import InventoryFileError, read_inventory_files
from app.inventory_render import merge, static_data, target_hosts
from app.inventory_sources import (
    SourceError,
    check_config,
    effective_interval,
    enqueue_refresh,
    has_sources,
    is_constructed,
    refresh_rows,
)
from app.models import (
    Credential,
    GitSnapshot,
    GitSource,
    Inventory,
    InventoryRefresh,
    InventorySnapshot,
    InventorySource,
    InventorySourceOutput,
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
    RefreshSourceOut,
    SnapshotGroup,
    SnapshotOut,
    SourceCreate,
    SourceOut,
    SourceUpdate,
    TargetGroup,
    Targets,
)
from app.scoping import get_scoped
from app.scrub import mask_for_display

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
    output = db.get(InventorySourceOutput, source.id)
    git_source = db.get(GitSource, source.git_source_id) if source.git_source_id else None
    interval = effective_interval(source, source.inventory)
    next_at = None
    if interval and source.enabled and source.last_queued_at is not None:
        next_at = source.last_queued_at + timedelta(seconds=interval)
    return {
        **SourceOut.model_validate(source).model_dump(),
        "effective_interval_seconds": interval,
        "next_refresh_at": next_at,
        "credential_name": credential.name if credential else None,
        "output_refreshed_at": output.refreshed_at if output else None,
        "output_host_count": output.host_count if output else None,
        "output_group_count": output.group_count if output else None,
        "output_warnings": (output.warnings or []) if output else [],
        "output_git_commit": output.git_commit if output else None,
        "git_source_name": git_source.name if git_source else None,
    }


def _refresh_out(db: Session, refresh: InventoryRefresh | None) -> RefreshOut | None:
    if refresh is None:
        return None
    out = RefreshOut.model_validate(refresh)
    out.source_results = [RefreshSourceOut.model_validate(row) for row in refresh_rows(db, refresh)]
    return out


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


def _check_git_file(db: Session, inventory: Inventory, git_source_id: int, path: str) -> str:
    """The path, once its git source (of the inventory's project) has it in its current
    commit; 400 otherwise."""
    git_source = db.get(GitSource, git_source_id)
    if git_source is None or git_source.project_id != inventory.project_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Pick a git source of this project")
    snapshot = (
        db.get(GitSnapshot, git_source.current_snapshot_id)
        if git_source.current_snapshot_id
        else None
    )
    if snapshot is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sync the git source first")
    try:
        return read_inventory_files(snapshot, path).target
    except InventoryFileError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None


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


def _sources_changed(
    db: Session, inventory: Inventory, user: User, source_ids: list[int] | None = None
) -> None:
    """Refresh with the new sources: run `source_ids` (a new or changed source), the others
    contributing what they found last ([]: only combine again). Without any, the inventory has
    no snapshot."""
    # Constructed sources never run on their own: they are re-applied in every refresh.
    runs = [s.id for s in inventory.sources if s.id in (source_ids or []) and not is_constructed(s)]
    queued = enqueue_refresh(db, inventory, "sources_changed", user.username, source_ids=runs)
    if not has_sources(db, inventory.id):
        inventory.current_snapshot_id = None
    db.commit()  # also when it merged into a queued refresh, which it widened
    if queued is not None:
        notifier.notify(QUEUE_TOPIC)


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
    if payload.kind == "git_file":
        plugin, path = "file", _check_git_file(db, inventory, payload.git_source_id, payload.path)
    else:
        plugin, path = _plugin(payload.config), None
    _check_credential(db, inventory, payload.credential_id)
    source = InventorySource(
        inventory_id=inventory.id,
        name=payload.name.strip(),
        kind=payload.kind,
        plugin=plugin,
        config=payload.config,
        git_source_id=payload.git_source_id,
        path=path,
        credential_id=payload.credential_id,
        enabled=payload.enabled,
        position=payload.position,
        refresh_interval_seconds=payload.refresh_interval_seconds,
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
    _sources_changed(db, inventory, user, [source.id])
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
    git = source.kind == "git_file"
    if git and ({"config", "credential_id"} & set(values)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A git file source has no config")
    if not git and ({"git_source_id", "path"} & set(values)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A plugin source has no git source")
    # What it finds can change: it runs (again) in the next refresh.
    rerun = (
        values.get("config", source.config) != source.config
        or values.get("credential_id", source.credential_id) != source.credential_id
        or values.get("git_source_id", source.git_source_id) != source.git_source_id
        or values.get("path", source.path) != source.path
        or (values.get("enabled") is True and not source.enabled)
    )
    if git and ("git_source_id" in values or "path" in values):
        source.path = _check_git_file(
            db,
            inventory,
            values.get("git_source_id") or source.git_source_id,
            values.get("path") or source.path,
        )
        source.git_source_id = values.get("git_source_id") or source.git_source_id
        source.missing_at = None
    if "config" in values:
        source.plugin = _plugin(values["config"])
        source.config = values["config"]
    if "credential_id" in values:
        _check_credential(db, inventory, values["credential_id"])
        source.credential_id = values["credential_id"]
    for key in ("enabled", "position"):
        if values.get(key) is not None:
            setattr(source, key, values[key])
    if "refresh_interval_seconds" in values:  # None: the inventory's again
        source.refresh_interval_seconds = values["refresh_interval_seconds"]
    if rerun:
        source.last_queued_at = None
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
    if set(values) - {"refresh_interval_seconds", "name"}:  # what the snapshot holds may change
        _sources_changed(db, inventory, user, [source.id] if rerun else [])
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


@router.post(
    "/sources/{source_id}/refresh",
    response_model=RefreshOut | None,
    status_code=status.HTTP_202_ACCEPTED,
)
def refresh_source(
    inventory_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_refresh),
    db: Session = Depends(get_db),
) -> RefreshOut | None:
    """Runs one source now (the others contribute what they found last), merged with a refresh
    already queued."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_WRITE)
    source = _source(db, inventory, source_id)
    if not source.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "This source is turned off")
    enqueue_refresh(db, inventory, "manual", user.username, source_ids=[source.id])
    db.commit()
    notifier.notify(QUEUE_TOPIC)
    _audit(db, "inventory.refresh_requested", user, request, inventory, source=source.name)
    queued = db.scalars(
        select(InventoryRefresh)
        .where(
            InventoryRefresh.inventory_id == inventory.id,
            InventoryRefresh.status == RunStatus.QUEUED.value,
        )
        .limit(1)
    ).first()
    return _refresh_out(db, queued)


@router.put("/refresh-settings", response_model=Targets)
def update_refresh_settings(
    inventory_id: int,
    payload: RefreshSettings,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> Targets:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    changed = payload.model_dump(exclude_none=True)
    for field, value in changed.items():
        setattr(inventory, field, value)
    db.commit()
    if changed:
        _audit(db, "inventory.refresh_settings", user, request, inventory, **changed)
    return _targets(db, inventory)


@router.post("/refresh", response_model=RefreshOut | None, status_code=status.HTTP_202_ACCEPTED)
def request_refresh(
    inventory_id: int,
    request: Request,
    user: User = Depends(_refresh),
    db: Session = Depends(get_db),
) -> RefreshOut | None:
    """Queues a refresh now (merged with one already queued)."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_WRITE)
    if not has_sources(db, inventory.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "This inventory has no enabled sources")
    enqueue_refresh(db, inventory, "manual", user.username)
    db.commit()
    notifier.notify(QUEUE_TOPIC)
    _audit(db, "inventory.refresh_requested", user, request, inventory)
    queued = db.scalars(
        select(InventoryRefresh)
        .where(
            InventoryRefresh.inventory_id == inventory.id,
            InventoryRefresh.status == RunStatus.QUEUED.value,
        )
        .limit(1)
    ).first()
    return _refresh_out(db, queued)


@router.get("/refreshes", response_model=list[RefreshOut])
def list_refreshes(
    inventory_id: int,
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[RefreshOut]:
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    refreshes = db.scalars(
        select(InventoryRefresh)
        .where(InventoryRefresh.inventory_id == inventory.id)
        .order_by(InventoryRefresh.id.desc())
        .limit(limit)
    )
    return [_refresh_out(db, refresh) for refresh in refreshes]


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
        vars=mask_for_display(data.get("vars") or {}),
        groups=[
            SnapshotGroup(
                name=name,
                hosts=len(group["hosts"]),
                children=group["children"],
                vars=mask_for_display(group["vars"]),
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
                vars=mask_for_display({str(k): v for k, v in graph["hosts"][name].items()}),
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
        last_refresh=_refresh_out(db, last),
        refresh_interval_seconds=inventory.refresh_interval_seconds,
        refresh_before_run=inventory.refresh_before_run,
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
