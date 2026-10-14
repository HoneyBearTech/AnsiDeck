"""Restricting an inventory's runs to its hosts (app.egress_allowlist): the setting, the
extra entries runs may also reach, and where each host's connections go.

Anyone who can see the inventory sees this; project admins (sources:manage, like host keys)
change it. A change applies to runs claimed from then on, queued ones included.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.egress_allowlist import egress_targets, parse_extras
from app.hardening import client_ip
from app.inventory_render import merge, static_data
from app.inventory_sources import has_sources
from app.models import Inventory, InventorySnapshot, User
from app.permissions import Permission, Scope, guard
from app.schemas.egress import (
    EgressExtraOut,
    EgressExtrasIn,
    EgressHost,
    EgressModeIn,
    EgressOut,
    EgressSummary,
)
from app.scoping import get_scoped

router = APIRouter()

_manage = guard(Permission.CONTENT_READ, Permission.SOURCES_MANAGE, scope=Scope.PROJECT)

PAGE_SIZE = 100


def _inventory(
    db: Session, user: User, request: Request, inventory_id: int, permission: Permission
) -> Inventory:
    return get_scoped(db, user, request, Inventory, inventory_id, permission, "Inventory not found")


def _graph(db: Session, inventory: Inventory) -> dict:
    """The inventory a run would see now (its own hosts and its sources')."""
    snapshot = None
    if inventory.current_snapshot_id is not None and has_sources(db, inventory.id):
        snapshot = db.get(InventorySnapshot, inventory.current_snapshot_id)
    return merge(static_data(inventory), snapshot.data if snapshot else None)


def _extras_out(inventory: Inventory) -> list[EgressExtraOut]:
    return [EgressExtraOut(**e) for e in inventory.egress_extras or []]


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


@router.get("/egress", response_model=EgressOut)
def get_egress(
    inventory_id: int,
    request: Request,
    q: str | None = Query(None, max_length=255),
    problems: bool = Query(False),
    page: int = Query(1, ge=1),
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> EgressOut:
    """The setting, its extra entries, and for each host (a page, filtered by `q` on the host
    or its address, and with `problems` to those whose address isn't known) where its
    connections go. Extra vars a run is started with can change an address."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    targets = egress_targets(_graph(db, inventory))
    counts = dict.fromkeys(("ok", "local", "indirect", "unknown"), 0)
    warnings: list[str] = []
    for target in targets.values():
        counts[target.status] += 1
        warnings += target.warnings
    needle = (q or "").lower()
    names = [
        h
        for h, t in targets.items()
        if (needle in h.lower() or needle in (t.address or ""))
        and not (problems and t.status != "unknown")
    ]
    hosts = []
    for host in names[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]:
        target = targets[host]
        jump = target.jump
        hosts.append(
            EgressHost(
                host=host,
                connection=target.connection,
                status=target.status,
                address=target.address,
                jump_host=f"{jump.host}:{jump.port}" if jump else None,
                reason=target.reason,
            )
        )
    return EgressOut(
        restricted=inventory.egress_restricted,
        extras=_extras_out(inventory),
        hosts=hosts,
        total=len(names),
        summary=EgressSummary(hosts=len(targets), **counts),
        warnings=warnings[:50],
    )


@router.put("/egress/mode", response_model=EgressModeIn)
def set_egress_mode(
    inventory_id: int,
    body: EgressModeIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> EgressModeIn:
    """Applies to runs claimed from now on (queued ones included); running runs keep theirs."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    previous = inventory.egress_restricted
    if previous != body.restricted:
        inventory.egress_restricted = body.restricted
        db.commit()
        _audit(
            db, "inventory.egress_mode", user, request, inventory,
            old=previous, new=body.restricted,
        )  # fmt: skip
    return EgressModeIn(restricted=inventory.egress_restricted)


@router.put("/egress/extras", response_model=list[EgressExtraOut])
def set_egress_extras(
    inventory_id: int,
    body: EgressExtrasIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[EgressExtraOut]:
    """Replaces the extra entries (addresses, networks or host names, with ports or not)."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    try:
        extras = parse_extras([e.model_dump() for e in body.extras])
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    before = {_label(e) for e in inventory.egress_extras or []}
    after = {_label(e) for e in extras}
    inventory.egress_extras = extras or None
    db.commit()
    if before != after:
        changes = {"added": sorted(after - before)[:50], "removed": sorted(before - after)[:50]}
        _audit(
            db, "inventory.egress_extras", user, request, inventory,
            **{k: v for k, v in changes.items() if v}, count=len(extras),
        )  # fmt: skip
    return _extras_out(inventory)


def _label(extra: dict) -> str:
    ports = extra.get("ports")
    if not ports:
        return extra["target"]
    listed = ",".join(f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in ports)
    return f"{extra['target']} {listed}"
