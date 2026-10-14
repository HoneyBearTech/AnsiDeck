"""Host key scans: ssh-keyscan of an inventory's hosts by a worker, so a project admin can
trust the keys they present before a host's first run (and confirm learned ones).

A scan runs in a worker slot like a playbook check (claim, lease, one-time job token): as a
slot user, behind the worker's egress filter, from where the runs connect. What comes back is
untrusted until an admin trusts a key (app.host_key_store.trust copies it from the scan);
scans are pruned an hour after they end.
"""

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.host_keys import HostAddress, normalise_name, parse_known_hosts
from app.models import HostKeyScan, Inventory, RunStatus, User
from app.queue import online_slots

MAX_TARGETS = 500
MAX_EXTRA = 20
TIMEOUT_SECONDS = 90
# A scan nobody claims in this long fails with the reason it waited (e.g. only workers from
# before scans existed).
QUEUE_TIMEOUT_SECONDS = 120
RETENTION_SECONDS = 3600
TIMEOUT_GRACE_SECONDS = 30
MAX_RESULTS = 3 * MAX_TARGETS  # rsa, ecdsa and ed25519 per target


class ScanError(ValueError):
    """The scan can't be started as asked (its message is safe to show)."""


def split_name(name: str) -> tuple[str, int]:
    """`[host]:port` or `host` (port 22) to what ssh-keyscan connects to."""
    if name.startswith("["):
        host, port = name[1:].rsplit("]:", 1)
        return host, int(port)
    return name, 22


def scan_targets(
    addresses: dict[str, HostAddress], hosts: list[str] | None, extra: list[str]
) -> list[dict]:
    """What to scan: the given inventory hosts (all when None) that connect with ssh to an
    address known in advance, plus extra names (jump hosts) as known_hosts names."""
    names: dict[str, None] = {}
    wanted = addresses.keys() if hosts is None else hosts
    for host in wanted:
        address = addresses.get(host)
        if address is None:
            raise ScanError(f"{host[:100]} is not a host of this inventory")
        if address.name is not None:
            names[address.name] = None
    if len(extra) > MAX_EXTRA:
        raise ScanError(f"at most {MAX_EXTRA} extra names")
    for raw in extra:
        name = normalise_name(raw)
        if name is None:
            raise ScanError(f"{raw[:100]!r} is not a host name or [host]:port")
        names[name] = None
    if not names:
        raise ScanError("none of these hosts has an address known before a run")
    if len(names) > MAX_TARGETS:
        raise ScanError(f"at most {MAX_TARGETS} addresses per scan; scan fewer hosts")
    return [{"name": n, "host": split_name(n)[0], "port": split_name(n)[1]} for n in names]


def enqueue_scan(
    db: Session, inventory: Inventory, user: User, targets: list[dict]
) -> tuple[HostKeyScan, bool]:
    """Queues a scan, or returns the inventory's scan already waiting or running; and whether
    it is new. The caller commits, then wakes the workers (QUEUE_TOPIC)."""
    busy = db.scalars(
        select(HostKeyScan)
        .where(
            HostKeyScan.inventory_id == inventory.id,
            HostKeyScan.status.in_((RunStatus.QUEUED.value, RunStatus.RUNNING.value)),
        )
        .limit(1)
    ).first()
    if busy is not None:
        return busy, False
    scan = HostKeyScan(
        inventory_id=inventory.id,
        requested_by_user_id=user.id,
        requested_by=user.username,
        targets=targets,
        status=RunStatus.QUEUED.value,
        timeout_seconds=TIMEOUT_SECONDS,
    )
    db.add(scan)
    db.flush()
    return scan, True


def build_scan_job(scan: HostKeyScan) -> dict:
    return {
        "kind": "keyscan",
        "targets": [{"host": t["host"], "port": t["port"]} for t in scan.targets],
        "timeout_seconds": scan.timeout_seconds,
    }


def scanned_keys(scan: HostKeyScan, lines: list[str]) -> list[dict]:
    """The keys ssh-keyscan printed for the scan's own targets (anything else is dropped)."""
    wanted = {t["name"] for t in scan.targets}
    keys, _ = parse_known_hosts("\n".join(lines), MAX_RESULTS)
    return [
        {"name": k.name, "key_type": k.key_type, "key_b64": k.key_b64, "fingerprint": k.fingerprint}
        for k in keys
        if k.name in wanted
    ]


def end_scan(
    scan: HostKeyScan, status: str, *, error: str | None = None, results: list | None = None
) -> None:
    """Records the outcome; the claim goes. The caller holds the row lock and commits."""
    scan.status = status
    scan.finished_at = func.now()
    scan.lease_expires_at = None
    scan.claim_token_hash = None
    scan.job_token_hash = None
    scan.job_token_expires_at = None
    scan.error = error[:1000] if error else None
    if results is not None:
        scan.results = results


def wait_reason(db: Session) -> str:
    if online_slots(db) == 0:
        return "No worker is online: start one to scan host keys"
    return "Waiting for a worker that can scan host keys…"


def prune_scans(db: Session) -> int:
    """Deletes scans that ended over RETENTION_SECONDS ago (the caller commits)."""
    cutoff = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, RETENTION_SECONDS)
    return len(
        db.execute(
            delete(HostKeyScan)
            .where(HostKeyScan.finished_at.is_not(None), HostKeyScan.finished_at < cutoff)
            .returning(HostKeyScan.id)
        ).all()
    )
