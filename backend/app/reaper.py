"""Ends runs and installs that nobody will finish: a worker that stopped heartbeating (it
crashed, or lost the network), a run past its timeout that its worker didn't stop, a cancel
its worker never confirmed, queued runs whose playbook/inventory/credential... was deleted,
and installs whose API process died. Runs every few seconds in the API (reap_once()).
"""

import logging
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_sessionmaker
from app.galaxy import try_start_install
from app.git_sync import prune_snapshots
from app.inventory_sources import due_inventories, end_refresh, enqueue_refresh
from app.inventory_sources import prune_snapshots as prune_inventory_snapshots
from app.jobs import UNRUNNABLE, unrunnable_reason
from app.models import GalaxyInstall, InventoryRefresh, Run, RunStatus, Worker
from app.notifications import WORKER_OFFLINE, WORKER_UNISOLATED
from app.notifications.alerts import clear_alerts
from app.notifications.dispatch import prune as prune_deliveries
from app.notifications.ops import check_queue, check_workers
from app.notify import notifier, run_topic
from app.queue import QUEUE_TOPIC, fail_run
from app.run_executor import format_duration
from app.storage import inventory_refresh_output_path

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 5.0
# Workers enforce timeouts and cancels themselves; these are the backstops' extra patience.
TIMEOUT_GRACE_SECONDS = 120
CANCEL_GRACE_SECONDS = 90
# Workers not seen for this long drop off the Workers page.
WORKER_RETENTION_SECONDS = 24 * 60 * 60
_BATCH = 100


def _at(value: datetime | None) -> str:
    return f"{value:%Y-%m-%d %H:%M:%S} UTC" if value else "never"


def _lock(db: Session, *where) -> list[Run]:
    return list(
        db.scalars(
            select(Run)
            .where(*where)
            .order_by(Run.id)
            .limit(_BATCH)
            .with_for_update(skip_locked=True)
        )
    )


def reap_refreshes(db: Session) -> list[dict]:
    """Inventory refreshes (Phase 4G): ends those whose worker went away or overran, queues
    the scheduled ones and prunes old snapshots. Returns the audit events to record."""
    pending: list[dict] = []

    def lock(*where) -> list[InventoryRefresh]:
        return list(
            db.scalars(
                select(InventoryRefresh)
                .where(InventoryRefresh.status == RunStatus.RUNNING.value, *where)
                .order_by(InventoryRefresh.id)
                .limit(_BATCH)
                .with_for_update(skip_locked=True)
            )
        )

    for refresh in lock(InventoryRefresh.lease_expires_at < func.now()):
        why = (
            f"worker lost: no heartbeat from {refresh.worker_id} since {_at(refresh.heartbeat_at)}"
        )
        if audit_event := end_refresh(db, refresh, RunStatus.FAILED.value, why):
            pending.append(audit_event)
        inventory_refresh_output_path(refresh.id).unlink(missing_ok=True)
    db.commit()
    began = func.coalesce(InventoryRefresh.started_at, InventoryRefresh.claimed_at)
    limit = func.make_interval(
        0, 0, 0, 0, 0, 0, InventoryRefresh.timeout_seconds + TIMEOUT_GRACE_SECONDS
    )
    for refresh in lock(began + limit < func.now()):
        took = format_duration(refresh.timeout_seconds)
        why = f"timed out after {took} (its worker did not stop it)"
        if audit_event := end_refresh(db, refresh, RunStatus.TIMED_OUT.value, why):
            pending.append(audit_event)
        inventory_refresh_output_path(refresh.id).unlink(missing_ok=True)
    db.commit()

    queued = False
    for inventory in due_inventories(db):
        queued = enqueue_refresh(db, inventory, "schedule") is not None or queued
    db.commit()
    if queued:
        notifier.notify(QUEUE_TOPIC)
    prune_inventory_snapshots(db)
    db.commit()
    return pending


def reap_once() -> list[int]:
    """One pass; returns the ids of the runs it ended."""
    ended: list[tuple[int, str | None, int, str | None]] = []  # id, audit action, project, worker
    pending_audits: list[dict] = []
    db = get_sessionmaker()()
    try:
        running = Run.status == RunStatus.RUNNING.value
        for run in _lock(db, running, Run.lease_expires_at < func.now()):
            fail_run(
                run,
                RunStatus.FAILED,
                f"worker lost: no heartbeat from {run.worker_id} since {_at(run.heartbeat_at)}",
            )
            ended.append((run.id, "run.worker_lost", run.project_id, run.worker_id))
        db.commit()

        began = func.coalesce(Run.started_at, Run.claimed_at)
        limit = func.make_interval(0, 0, 0, 0, 0, 0, Run.timeout_seconds + TIMEOUT_GRACE_SECONDS)
        for run in _lock(db, running, began + limit < func.now()):
            fail_run(
                run,
                RunStatus.TIMED_OUT,
                f"timed out after {format_duration(run.timeout_seconds)} "
                "(its worker did not stop it)",
            )
            ended.append((run.id, "run.timed_out", run.project_id, run.worker_id))
        db.commit()

        grace = func.make_interval(0, 0, 0, 0, 0, 0, CANCEL_GRACE_SECONDS)
        for run in _lock(db, running, Run.cancel_requested_at + grace < func.now()):
            fail_run(
                run,
                RunStatus.CANCELLED,
                f"cancelled by {run.cancel_requested_by} (its worker did not confirm)",
            )
            ended.append((run.id, None, run.project_id, run.worker_id))
        db.commit()

        for run in _lock(db, Run.status == RunStatus.QUEUED.value, UNRUNNABLE):
            fail_run(run, RunStatus.FAILED, f"not run: {unrunnable_reason(run)}")
            ended.append((run.id, None, run.project_id, None))
        db.commit()

        for install in db.scalars(
            select(GalaxyInstall)
            .where(
                GalaxyInstall.status == RunStatus.RUNNING.value,
                GalaxyInstall.lease_expires_at < func.now(),
            )
            .with_for_update(skip_locked=True)
        ):
            install.status = RunStatus.FAILED.value
            install.status_reason = "interrupted: the API process running it went away"
            install.finished_at = func.now()
            install.lease_expires_at = None
        db.commit()

        try:
            pending_audits += reap_refreshes(db)
        except Exception:  # the next pass tries again
            db.rollback()
            logger.exception("could not reap inventory refreshes")

        retention = func.make_interval(0, 0, 0, 0, 0, 0, WORKER_RETENTION_SECONDS)
        gone = db.scalars(
            delete(Worker).where(Worker.last_seen_at < func.now() - retention).returning(Worker.id)
        ).all()
        clear_alerts(
            db, [f"{event}:{w}" for w in gone for event in (WORKER_OFFLINE, WORKER_UNISOLATED)]
        )
        prune_deliveries(db)
        db.commit()
        try:
            prune_snapshots(db)
        except Exception:  # the next pass tries again
            db.rollback()
            logger.exception("could not prune git snapshots")

        for check in (lambda: check_workers(db, WORKER_RETENTION_SECONDS), lambda: check_queue(db)):
            try:
                with db.begin_nested():
                    check()
            except Exception:  # notifications must never stop the reaper
                logger.exception("notification check failed")
        db.commit()

        for pending in pending_audits:
            audit.record(db, **pending)
        for run_id, action, project_id, worker_id in ended:
            notifier.notify(run_topic(run_id))
            if action:
                audit.record(
                    db,
                    action,
                    outcome="failure",
                    actor_username=worker_id,
                    target_type="run",
                    target_id=run_id,
                    project_id=project_id,
                )
    finally:
        db.rollback()
        db.close()
    if ended:
        notifier.notify(QUEUE_TOPIC)
    try_start_install()
    return [run_id for run_id, *_ in ended]
