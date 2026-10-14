"""An inventory's SSH host keys (app.host_keys): which keys its runs trust, how each host is
covered, and the mode.

Anyone who can see the inventory sees its keys (fingerprints only, never needed as secrets);
project admins (sources:manage, as for git sources' host keys) change the mode, trust pasted
keys, confirm learned ones and remove keys.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.host_key_scans import ScanError, enqueue_scan, scan_targets, wait_reason
from app.host_key_store import TooManyKeys, trust
from app.host_keys import HostAddress, KnownHost, host_addresses, parse_known_hosts
from app.inventory_render import merge, static_data
from app.inventory_sources import has_sources
from app.models import HostKeyScan, Inventory, InventoryHostKey, InventorySnapshot, RunStatus, User
from app.notify import notifier
from app.permissions import Permission, Scope, guard
from app.queue import QUEUE_TOPIC
from app.schemas.host_keys import (
    ConfirmIn,
    HostKeyHost,
    HostKeyOut,
    HostKeysOut,
    HostKeySummary,
    ModeIn,
    PastedKey,
    PasteIn,
    PasteOut,
    ScanIn,
    ScannedKey,
    ScanOut,
    TrustIn,
)
from app.scoping import get_scoped

router = APIRouter()

_manage = guard(Permission.CONTENT_READ, Permission.SOURCES_MANAGE, scope=Scope.PROJECT)

PAGE_SIZE = 100
_AUDITED_KEYS = 50


def _inventory(
    db: Session, user: User, request: Request, inventory_id: int, permission: Permission
) -> Inventory:
    return get_scoped(db, user, request, Inventory, inventory_id, permission, "Inventory not found")


def _addresses(db: Session, inventory: Inventory) -> dict[str, HostAddress]:
    """Where each host a run would see now connects (its own hosts and its sources')."""
    snapshot = None
    if inventory.current_snapshot_id is not None and has_sources(db, inventory.id):
        snapshot = db.get(InventorySnapshot, inventory.current_snapshot_id)
    return host_addresses(merge(static_data(inventory), snapshot.data if snapshot else None))


def _keys(db: Session, inventory: Inventory) -> list[InventoryHostKey]:
    return list(
        db.scalars(
            select(InventoryHostKey)
            .where(InventoryHostKey.inventory_id == inventory.id)
            .order_by(InventoryHostKey.name, InventoryHostKey.key_type)
        )
    )


def _users(addresses: dict[str, HostAddress]) -> dict[str, list[str]]:
    users: dict[str, list[str]] = {}
    for host in sorted(addresses):
        if (name := addresses[host].name) is not None:
            users.setdefault(name, []).append(host)
    return users


def _status(address: HostAddress, trusted: set[str], learned: set[str]) -> str:
    if not address.checked:
        return "not_checked"
    if address.name is None:
        return "unknown"
    if address.name in trusted:
        return "trusted"
    return "learned" if address.name in learned else "missing"


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


@router.get("/host-keys", response_model=HostKeysOut)
def list_host_keys(
    inventory_id: int,
    request: Request,
    q: str | None = Query(None, max_length=255),
    untrusted: bool = Query(False),
    page: int = Query(1, ge=1),
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> HostKeysOut:
    """The inventory's trusted keys and, for each host (a page, filtered by `q` on the host or
    its address, and with `untrusted` to those without a confirmed key), whether a run can
    check it."""
    inventory = _inventory(db, user, request, inventory_id, Permission.CONTENT_READ)
    addresses = _addresses(db, inventory)
    users = _users(addresses)
    keys = _keys(db, inventory)
    trusted = {k.name for k in keys if k.confirmed}
    learned = {k.name for k in keys if not k.confirmed}
    statuses = {h: _status(a, trusted, learned) for h, a in addresses.items()}
    counts = dict.fromkeys(("trusted", "learned", "missing", "unknown", "not_checked"), 0)
    for value in statuses.values():
        counts[value] += 1
    needle = (q or "").lower()
    names = sorted(
        h
        for h, a in addresses.items()
        if (needle in h.lower() or needle in (a.name or ""))
        and not (untrusted and statuses[h] == "trusted")
    )
    hosts = [
        HostKeyHost(
            host=h,
            name=addresses[h].name,
            connection=addresses[h].connection,
            status=statuses[h],
            reason=addresses[h].reason,
        )
        for h in names[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    ]
    return HostKeysOut(
        mode=inventory.host_key_checking,
        keys=[
            HostKeyOut.model_validate(k).model_copy(update={"hosts": users.get(k.name, [])[:20]})
            for k in keys
        ],
        hosts=hosts,
        total=len(names),
        summary=HostKeySummary(hosts=len(addresses), **counts),
    )


@router.put("/host-keys/mode", response_model=ModeIn)
def set_mode(
    inventory_id: int,
    body: ModeIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> ModeIn:
    """Applies to runs claimed from now on (queued ones included)."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    previous = inventory.host_key_checking
    if previous != body.mode:
        inventory.host_key_checking = body.mode
        db.commit()
        _audit(db, "inventory.host_key_mode", user, request, inventory, old=previous, new=body.mode)
    return ModeIn(mode=inventory.host_key_checking)


@router.post("/host-keys/paste", response_model=PasteOut)
def paste_host_keys(
    inventory_id: int,
    body: PasteIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> PasteOut:
    """Trusts the keys in known_hosts text (one plain name per key; a key replaces the
    inventory's key of the same name and type). With dry_run, only says what would change."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    pasted, warnings = parse_known_hosts(body.known_hosts)
    if not pasted:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "No usable key in what was pasted" + (f": {warnings[0]}" if warnings else ""),
        )
    users = _users(_addresses(db, inventory))
    existing = {(k.name, k.key_type): k for k in _keys(db, inventory)}
    result = []
    for key in pasted:
        row = existing.get((key.name, key.key_type))
        if row is None:
            change, previous = "new", None
        elif row.key_b64 != key.key_b64:
            change, previous = "replace", row.fingerprint
        else:
            change, previous = ("same" if row.confirmed else "confirm"), None
        result.append(
            PastedKey(
                name=key.name,
                key_type=key.key_type,
                fingerprint=key.fingerprint,
                change=change,
                previous=previous,
                hosts=users.get(key.name, [])[:20],
            )
        )
    if not users.keys() & {k.name for k in pasted}:
        warnings.append("no host of this inventory connects to any of these names")
    if body.dry_run:
        return PasteOut(keys=result, warnings=warnings)
    try:
        changes = trust(db, inventory, pasted, "paste", user.username)
    except TooManyKeys as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    db.commit()
    if changes:
        _audit(
            db,
            "inventory.trust_host_key",
            user,
            request,
            inventory,
            keys=changes[:_AUDITED_KEYS],
            count=len(changes),
        )
    return PasteOut(keys=result, warnings=warnings)


@router.post("/host-keys/confirm", response_model=list[HostKeyOut])
def confirm_host_keys(
    inventory_id: int,
    body: ConfirmIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[HostKeyOut]:
    """Confirms learned keys, so strict runs trust them too. Ids of other inventories' keys
    are ignored."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    rows = list(
        db.scalars(
            select(InventoryHostKey).where(
                InventoryHostKey.inventory_id == inventory.id,
                InventoryHostKey.id.in_(set(body.ids)),
                InventoryHostKey.confirmed.is_(False),
            )
        )
    )
    for row in rows:
        row.confirmed, row.confirmed_by, row.confirmed_at = True, user.username, func.now()
    db.commit()
    if rows:
        _audit(
            db,
            "inventory.confirm_host_key",
            user,
            request,
            inventory,
            keys=[
                {"name": r.name, "key_type": r.key_type, "fingerprint": r.fingerprint}
                for r in rows[:_AUDITED_KEYS]
            ],
            count=len(rows),
        )
    return [HostKeyOut.model_validate(r) for r in rows]


@router.delete("/host-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_host_key(
    inventory_id: int,
    key_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> None:
    """Forgets a key: in accept_new mode the host's next key is learned again, in strict mode
    its runs fail until a key is trusted."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    row = db.get(InventoryHostKey, key_id)
    if row is None or row.inventory_id != inventory.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host key not found")
    detail = {"name": row.name, "key_type": row.key_type, "fingerprint": row.fingerprint}
    db.delete(row)
    db.commit()
    _audit(db, "inventory.remove_host_key", user, request, inventory, **detail)


def _scan(db: Session, inventory: Inventory, scan_id: int) -> HostKeyScan:
    scan = db.get(HostKeyScan, scan_id)
    if scan is None or scan.inventory_id != inventory.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


def _scan_out(db: Session, inventory: Inventory, scan: HostKeyScan) -> ScanOut:
    users = _users(_addresses(db, inventory))
    existing = {(k.name, k.key_type): k for k in _keys(db, inventory)}
    keys = []
    for found in scan.results or []:
        row = existing.get((found["name"], found["key_type"]))
        if row is None:
            state, previous = "new", None
        elif row.key_b64 != found["key_b64"]:
            state, previous = "changed", row.fingerprint
        else:
            state, previous = ("trusted" if row.confirmed else "learned"), None
        keys.append(
            ScannedKey(
                name=found["name"],
                key_type=found["key_type"],
                fingerprint=found["fingerprint"],
                hosts=users.get(found["name"], [])[:20],
                state=state,
                previous=previous,
            )
        )
    answered = {k["name"] for k in scan.results or []}
    finished = scan.status not in (RunStatus.QUEUED.value, RunStatus.RUNNING.value)
    return ScanOut(
        id=scan.id,
        status=scan.status,
        wait_reason=wait_reason(db) if scan.status == RunStatus.QUEUED.value else None,
        error=scan.error,
        requested_by=scan.requested_by,
        queued_at=scan.queued_at,
        finished_at=scan.finished_at,
        targets=len(scan.targets),
        keys=keys,
        silent=[t["name"] for t in scan.targets if t["name"] not in answered] if finished else [],
    )


@router.post("/host-key-scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    inventory_id: int,
    body: ScanIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Scans the hosts' SSH keys from a worker (where runs connect from). Returns the
    inventory's scan already waiting or running instead of starting another."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    try:
        targets = scan_targets(_addresses(db, inventory), body.hosts, body.extra)
    except ScanError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    scan, new = enqueue_scan(db, inventory, user, targets)
    db.commit()
    if new:
        notifier.notify(QUEUE_TOPIC)
        _audit(db, "inventory.host_key_scan", user, request, inventory, targets=len(targets))
    return _scan_out(db, inventory, scan)


@router.get("/host-key-scans/{scan_id}", response_model=ScanOut)
def get_scan(
    inventory_id: int,
    scan_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> ScanOut:
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    return _scan_out(db, inventory, _scan(db, inventory, scan_id))


@router.post("/host-keys/trust", response_model=list[HostKeyOut])
def trust_scanned_keys(
    inventory_id: int,
    body: TrustIn,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[HostKeyOut]:
    """Trusts keys a scan of this inventory found: the keys come from the scan, never from
    the request. A key replaces the inventory's key of the same name and type; trusting a
    learned key confirms it."""
    inventory = _inventory(db, user, request, inventory_id, Permission.SOURCES_MANAGE)
    scan = _scan(db, inventory, body.scan_id)
    found = {(k["name"], k["key_type"]): k for k in scan.results or []}
    chosen = []
    for item in body.keys:
        key = found.get((item.name, item.key_type))
        if key is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"The scan found no {item.key_type[:64]} key for {item.name[:300]}",
            )
        chosen.append(KnownHost(key["name"], key["key_type"], key["key_b64"], key["fingerprint"]))
    try:
        changes = trust(db, inventory, chosen, "scan", user.username)
    except TooManyKeys as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    db.commit()
    if changes:
        _audit(
            db,
            "inventory.trust_host_key",
            user,
            request,
            inventory,
            source="scan",
            scan_id=scan.id,
            keys=changes[:_AUDITED_KEYS],
            count=len(changes),
        )
    names = {(k.name, k.key_type) for k in chosen}
    return [
        HostKeyOut.model_validate(k) for k in _keys(db, inventory) if (k.name, k.key_type) in names
    ]
