"""An inventory's trusted SSH host keys (app.host_keys): what a run's job carries, what a run
learned or had refused, and keys an admin trusts. Callers commit and audit."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.host_keys import (
    MAX_LEARNED_LINES,
    MAX_PROBLEMS,
    KnownHost,
    host_addresses,
    parse_known_hosts,
)
from app.models import Inventory, InventoryHostKey, Run

MAX_KEYS = 2000  # per inventory


class TooManyKeys(ValueError):
    pass


def known_hosts_text(db: Session, inventory_id: int, *, confirmed_only: bool) -> str:
    query = select(InventoryHostKey).where(InventoryHostKey.inventory_id == inventory_id)
    if confirmed_only:
        query = query.where(InventoryHostKey.confirmed)
    keys = db.scalars(query.order_by(InventoryHostKey.name, InventoryHostKey.key_type))
    return "".join(f"{k.name} {k.key_type} {k.key_b64}\n" for k in keys)


def job_host_keys(db: Session, run: Run) -> dict | None:
    """{"mode", "known_hosts"} for a run that checks host keys (its mode was fixed when it was
    claimed), None for one that doesn't. Strict runs trust confirmed keys only."""
    mode = run.host_key_checking
    if mode not in ("accept_new", "strict") or run.inventory_id is None:
        return None
    return {
        "mode": mode,
        "known_hosts": known_hosts_text(db, run.inventory_id, confirmed_only=mode == "strict"),
    }


def _keys_by_name(db: Session, inventory_id: int) -> dict[tuple[str, str], InventoryHostKey]:
    rows = db.scalars(select(InventoryHostKey).where(InventoryHostKey.inventory_id == inventory_id))
    return {(row.name, row.key_type): row for row in rows}


def record_learned(db: Session, run: Run, lines: list[str]) -> list[dict]:
    """Stores the keys an accept_new run's ssh learned, unconfirmed. The file they come from is
    writable by the playbook, so only keys for an address a host of the run's own inventory
    connects to, and that had no key at all, are kept (one per address). Returns what was
    stored, for the audit log."""
    from app.jobs import run_graph  # app.jobs imports this module

    if run.host_key_checking != "accept_new" or run.inventory_id is None:
        return []
    run.host_keys_learned = 0
    inventory = db.get(Inventory, run.inventory_id)
    if not lines or inventory is None or inventory.project_id != run.project_id:
        return []
    learned, _ = parse_known_hosts("\n".join(lines[:MAX_LEARNED_LINES]), MAX_LEARNED_LINES)
    try:
        addresses = host_addresses(run_graph(db, run, inventory))
    except RuntimeError:
        return []
    owners: dict[str, str] = {}
    for host, address in addresses.items():
        if address.name is not None:
            owners.setdefault(address.name, host)
    known = {name for name, _ in _keys_by_name(db, inventory.id)}
    count = db.scalar(select(func.count()).where(InventoryHostKey.inventory_id == inventory.id))
    stored: list[dict] = []
    for key in learned:
        if key.name not in owners or key.name in known or count >= MAX_KEYS:
            continue
        known.add(key.name)
        count += 1
        db.add(
            InventoryHostKey(
                inventory_id=inventory.id,
                name=key.name,
                key_type=key.key_type,
                key_b64=key.key_b64,
                fingerprint=key.fingerprint,
                source="learned",
                confirmed=False,
                run_id=run.id,
                created_by=f"run #{run.id}",
            )
        )
        stored.append({"name": key.name, "host": owners[key.name], "fingerprint": key.fingerprint})
    run.host_keys_learned = len(stored)
    return stored


def record_problems(run: Run, problems: list[dict]) -> None:
    """Keeps what ssh refused on the run, and says so in its reason if it has none."""
    if not problems:
        return
    problems = problems[:MAX_PROBLEMS]
    run.host_key_problems = problems
    if not run.status_reason:
        hosts = sorted({p["host"] for p in problems})
        shown = ", ".join(hosts[:5]) + (f" and {len(hosts) - 5} more" if len(hosts) > 5 else "")
        changed = any(p["problem"] == "changed" for p in problems)
        what = "changed for" if changed else "verification failed for"
        run.status_reason = f"SSH host key {what} {shown}"[:500]


def trust(
    db: Session, inventory: Inventory, keys: list[KnownHost], source: str, username: str
) -> list[dict]:
    """Trusts `keys` (confirmed): a key replaces the inventory's key of the same name and type.
    Returns the changes ({name, key_type, fingerprint, previous}); TooManyKeys past MAX_KEYS."""
    existing = _keys_by_name(db, inventory.id)
    new = {(k.name, k.key_type) for k in keys} - existing.keys()
    if len(existing) + len(new) > MAX_KEYS:
        raise TooManyKeys(f"an inventory can have at most {MAX_KEYS} host keys")
    changes: list[dict] = []
    now = func.now()
    for key in keys:
        row = existing.get((key.name, key.key_type))
        if row is not None and row.key_b64 == key.key_b64:
            if not row.confirmed:
                row.confirmed, row.confirmed_by, row.confirmed_at = True, username, now
                changes.append(
                    {"name": key.name, "key_type": key.key_type, "fingerprint": key.fingerprint,
                     "previous": None, "confirmed": True}
                )  # fmt: skip
            continue
        changes.append(
            {"name": key.name, "key_type": key.key_type, "fingerprint": key.fingerprint,
             "previous": row.fingerprint if row is not None else None}
        )  # fmt: skip
        if row is None:
            row = InventoryHostKey(inventory_id=inventory.id, name=key.name, key_type=key.key_type)
            db.add(row)
            existing[(key.name, key.key_type)] = row
        row.key_b64, row.fingerprint, row.source = key.key_b64, key.fingerprint, source
        row.confirmed, row.run_id = True, None
        row.created_by, row.created_at = username, now
        row.confirmed_by, row.confirmed_at = username, now
    return changes
