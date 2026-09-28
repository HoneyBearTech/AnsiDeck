from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Run, RunStatus, Worker
from app.permissions import Permission, Scope, require_permission
from app.queue import WORKER_ONLINE_SECONDS
from app.schemas.workers import WorkerOut

router = APIRouter(
    dependencies=[Depends(require_permission(Permission.WORKERS_READ, scope=Scope.GLOBAL))]
)


@router.get("", response_model=list[WorkerOut])
def list_workers(db: Session = Depends(get_db)) -> list[WorkerOut]:
    """Workers seen in the last day, online ones first."""
    since = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, WORKER_ONLINE_SECONDS)
    running = (
        select(func.count())
        .where(Run.worker_id == Worker.id, Run.status == RunStatus.RUNNING.value)
        .scalar_subquery()
    )
    rows = db.execute(
        select(Worker, running, Worker.last_seen_at > since).order_by(
            Worker.last_seen_at.desc(), Worker.id
        )
    ).all()
    return [
        WorkerOut(
            id=worker.id,
            slots=worker.slots,
            running=busy,
            online=online,
            first_seen_at=worker.first_seen_at,
            last_seen_at=worker.last_seen_at,
        )
        for worker, busy, online in rows
    ]
