"""Events into the outbox. emit() adds one notification_deliveries row per channel that wants
the event, in the caller's transaction: the notification exists exactly when what it reports
was committed, and survives a restart until it is sent."""

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import event as sa_event
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import NotificationChannel, NotificationDelivery, Project, Run, RunStatus
from app.notifications import EVENTS, RUN_FAILED, RUN_RECOVERED
from app.notify import notifier
from app.storage import run_log_path

logger = logging.getLogger(__name__)

DELIVERY_TOPIC = "notifications"
MAX_FAILED_TASKS = 10
_FINISHED = (RunStatus.SUCCESS.value, RunStatus.FAILED.value, RunStatus.TIMED_OUT.value)


def _wake_dispatcher(_session: Session) -> None:
    notifier.notify(DELIVERY_TOPIC)


def emit(
    db: Session, event: str, *, project_id: int | None, data: dict, dedup_key: str | None = None
) -> int:
    """Queues `event` for every enabled channel subscribed to it: the project's own and the
    global ones (project events), or the global ones only (global events). Returns how many."""
    info = EVENTS[event]
    scope = NotificationChannel.project_id.is_(None)
    if info.project and project_id is not None:
        scope = or_(scope, NotificationChannel.project_id == project_id)
    channels = [
        c
        for c in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled, scope))
        if event in (c.events or [])
    ]
    for channel in channels:
        db.execute(
            insert(NotificationDelivery)
            .values(channel_id=channel.id, event=event, payload=data, dedup_key=dedup_key)
            .on_conflict_do_nothing(index_elements=["channel_id", "dedup_key"])
        )
    if channels:
        sa_event.listen(db, "after_commit", _wake_dispatcher, once=True)
    return len(channels)


def _status(run: Run) -> str:
    return run.status.value if isinstance(run.status, RunStatus) else str(run.status)


def _previous_failed(db: Session, run: Run) -> bool:
    previous = db.scalar(
        select(Run.status)
        .where(
            Run.id != run.id,
            Run.project_id == run.project_id,
            Run.playbook_id == run.playbook_id,
            Run.inventory_id == run.inventory_id,
            Run.group_id.is_not_distinct_from(run.group_id),
            Run.status.in_(_FINISHED),
            Run.finished_at.is_not(None),
        )
        .order_by(Run.finished_at.desc(), Run.id.desc())
        .limit(1)
    )
    return previous in (RunStatus.FAILED.value, RunStatus.TIMED_OUT.value)


def run_finished(db: Session, run: Run) -> None:
    """Called with the run's final status set, before the commit that records it."""
    status = _status(run)
    if status in (RunStatus.FAILED.value, RunStatus.TIMED_OUT.value):
        event = RUN_FAILED
    elif status == RunStatus.SUCCESS.value and run.playbook_id and _previous_failed(db, run):
        event = RUN_RECOVERED
    else:
        return
    project = db.get(Project, run.project_id)
    data = {
        "run_id": run.id,
        "project": project.name if project else None,
        "playbook": run.playbook_name,
        "inventory": run.inventory_name,
        "group": run.group_name,
        "triggered_by": run.triggered_by,
        "status": status,
        "reason": run.status_reason,
        "hosts": {
            "total": run.hosts_total,
            "ok": run.hosts_ok,
            "changed": run.hosts_changed,
            "failed": run.hosts_failed,
            "unreachable": run.hosts_unreachable,
        },
        "finished_at": datetime.now(UTC).isoformat(),
    }
    # In a savepoint: a notification must never fail the commit of the run's own status.
    try:
        with db.begin_nested():
            emit(db, event, project_id=run.project_id, data=data)
    except Exception:
        logger.exception("could not queue %s for run %s", event, run.id)


def failed_tasks(run_id: int) -> list[dict]:
    """(host, task) of the failed and unreachable results in a finished run's log, which was
    scrubbed before it was written. Ignored failures don't count. Names only, no output."""
    found: list[dict] = []
    try:
        with open(run_log_path(run_id), encoding="utf-8") as log:
            for line in log:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                kind = event.get("event")
                data = event.get("event_data") or {}
                if kind == "runner_on_failed" and data.get("ignore_errors"):
                    continue
                if kind in ("runner_on_failed", "runner_on_unreachable"):
                    found.append(
                        {"host": str(data.get("host", "?")), "task": str(data.get("task", "?"))}
                    )
                    if len(found) >= MAX_FAILED_TASKS:
                        break
    except OSError:
        return []
    return found
