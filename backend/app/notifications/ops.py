"""Operations events: workers that stop reporting in or can't isolate runs, and a stuck
queue. Checked on every reaper pass and every worker claim/heartbeat; app.notifications.alerts
keeps each to one alert and one all-clear per episode."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Project, Run, RunStatus, Worker
from app.notifications import (
    INVENTORY_REFRESH_FAILED,
    QUEUE_STUCK,
    RESOLVED,
    SECRETS_UNAVAILABLE,
    WORKER_OFFLINE,
    WORKER_UNISOLATED,
)
from app.notifications.alerts import clear_alert, raise_alert
from app.notifications.events import emit

STUCK_SAMPLE = 20
# Waiting for these is a problem; waiting behind another run on the same inventory is not.
# ("Waiting for a worker…": slots look free, yet nothing claimed it for that long.)
_STUCK_REASONS = (
    "No worker is online",
    "Waiting for a free worker",
    "Waiting for a worker",
    "Waiting for a galaxy install",
)


def _ago(seconds: float):
    return func.now() - func.make_interval(0, 0, 0, 0, 0, 0, seconds)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def worker_seen(db: Session, worker_id: str, slots: int, isolated: bool | None) -> None:
    """On every claim and heartbeat (the caller commits)."""
    worker_id = worker_id[:255]
    if clear_alert(db, f"{WORKER_OFFLINE}:{worker_id}"):
        emit(
            db,
            WORKER_OFFLINE,
            project_id=None,
            data={"state": RESOLVED, "worker": worker_id, "slots": slots},
        )
    key = f"{WORKER_UNISOLATED}:{worker_id}"
    if isolated is False:
        if raise_alert(db, key):
            emit(db, WORKER_UNISOLATED, project_id=None, data={"worker": worker_id})
    elif isolated is True:
        clear_alert(db, key)  # fixed: no all-clear needed, the Workers page shows it


def check_workers(db: Session, retention_seconds: int) -> None:
    """Workers silent for NOTIFY_WORKER_OFFLINE_SECONDS (but not yet forgotten)."""
    silent = db.scalars(
        select(Worker).where(
            Worker.last_seen_at < _ago(get_settings().notify_worker_offline_seconds),
            Worker.last_seen_at > _ago(retention_seconds),
        )
    )
    for worker in silent:
        if raise_alert(db, f"{WORKER_OFFLINE}:{worker.id}"):
            emit(
                db,
                WORKER_OFFLINE,
                project_id=None,
                data={
                    "state": "offline",
                    "worker": worker.id,
                    "slots": worker.slots,
                    "last_seen_at": _iso(worker.last_seen_at),
                },
            )


def check_queue(db: Session) -> None:
    """Runs that waited NOTIFY_QUEUE_STUCK_MINUTES for a worker or a galaxy install."""
    from app.queue import wait_reason  # app.queue imports this module

    minutes = get_settings().notify_queue_stuck_minutes
    old = db.scalars(
        select(Run)
        .where(Run.status == RunStatus.QUEUED.value, Run.queued_at < _ago(minutes * 60))
        .order_by(Run.queued_at, Run.id)
        .limit(STUCK_SAMPLE)
    ).all()
    stuck = [
        (run, reason) for run in old if (reason := wait_reason(db, run)).startswith(_STUCK_REASONS)
    ]
    if stuck:
        oldest, reason = stuck[0]
        data = {
            "state": "stuck",
            "waiting": len(stuck),
            "minutes": minutes,
            "oldest_run_id": oldest.id,
            "queued_at": _iso(oldest.queued_at),
            "reason": reason,
        }
        if raise_alert(db, QUEUE_STUCK, data):
            emit(db, QUEUE_STUCK, project_id=None, data=data)
    elif clear_alert(db, QUEUE_STUCK):
        emit(db, QUEUE_STUCK, project_id=None, data={"state": RESOLVED})


def secret_store_failed(db: Session, kind: str, label: str) -> None:
    """The secret store can't be used (unreachable, sealed, TLS, login): alert once."""
    data = {"kind": kind, "label": label[:60]}
    if raise_alert(db, SECRETS_UNAVAILABLE, data):
        emit(db, SECRETS_UNAVAILABLE, project_id=None, data=data)


def secret_store_ok(db: Session, label: str) -> None:
    if clear_alert(db, SECRETS_UNAVAILABLE):
        emit(
            db, SECRETS_UNAVAILABLE, project_id=None, data={"state": RESOLVED, "label": label[:60]}
        )


def inventory_refresh_failed(db: Session, inventory, error: str) -> bool:
    """A refresh of an inventory's sources failed: alert once per failure streak. True when
    this one started the streak."""
    data = _inventory_data(db, inventory) | {"error": error[:300]}
    if raise_alert(db, f"{INVENTORY_REFRESH_FAILED}:{inventory.id}", data):
        emit(db, INVENTORY_REFRESH_FAILED, project_id=inventory.project_id, data=data)
        return True
    return False


def inventory_refresh_ok(db: Session, inventory) -> None:
    if clear_alert(db, f"{INVENTORY_REFRESH_FAILED}:{inventory.id}"):
        emit(
            db,
            INVENTORY_REFRESH_FAILED,
            project_id=inventory.project_id,
            data=_inventory_data(db, inventory) | {"state": RESOLVED},
        )


def _inventory_data(db: Session, inventory) -> dict:
    project = db.get(Project, inventory.project_id)
    return {
        "inventory_id": inventory.id,
        "inventory": inventory.name,
        "project": project.name if project else None,
    }
