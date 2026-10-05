"""The run queue lives in Postgres: a queued run is a `runs` row with status 'queued', and a
worker claims one with a single UPDATE ... FOR UPDATE SKIP LOCKED.

Rules, in this order:
- nothing is claimed while a galaxy install is queued or running (installs change the
  roles/collections runs load);
- one running run per inventory (also a partial unique index);
- per inventory, runs start in the order they were queued: only the oldest queued run of an
  inventory may be claimed, so a busy inventory's runs can't overtake each other.
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass

from psycopg.errors import UniqueViolation
from sqlalchemy import func, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from app import metrics
from app.config import get_settings
from app.db import GALAXY_GATE_KEY
from app.jobs import unrunnable_reason
from app.models import GalaxyInstall, Run, RunStatus, Worker
from app.notifications.events import run_finished
from app.notifications.ops import worker_seen
from app.notify import notifier, run_topic
from app.run_log import append_status_line

logger = logging.getLogger(__name__)

QUEUE_TOPIC = "queue"
JOB_TOKEN_SECONDS = 60
# Workers report in with every heartbeat (5 s) and every claim long poll (25 s at most).
WORKER_ONLINE_SECONDS = 30
_CLAIM_ATTEMPTS = 20
_ACTIVE = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)

_CLAIM = text(
    """
    WITH candidate AS (
        SELECT r.id FROM runs r
        WHERE r.status = 'queued'
          AND NOT EXISTS (
              SELECT 1 FROM runs busy
              WHERE busy.inventory_id = r.inventory_id AND busy.status = 'running')
          AND NOT EXISTS (
              SELECT 1 FROM runs earlier
              WHERE earlier.inventory_id = r.inventory_id AND earlier.status = 'queued'
                AND (earlier.queued_at, earlier.id) < (r.queued_at, r.id))
        ORDER BY r.queued_at, r.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE runs SET
        status = 'running',
        claimed_at = now(),
        heartbeat_at = now(),
        lease_expires_at = now() + make_interval(secs => :lease),
        worker_id = :worker_id,
        claim_token_hash = :claim_hash,
        job_token_hash = :job_hash,
        job_token_expires_at = now() + make_interval(secs => :job_ttl)
    FROM candidate
    WHERE runs.id = candidate.id
    RETURNING runs.id
    """
)


# An inventory refresh (Phase 4G) is claimed like a run: the oldest queued one whose inventory
# has none running. Runs don't wait for refreshes (they pin a snapshot when triggered).
_CLAIM_REFRESH = text(
    """
    WITH candidate AS (
        SELECT r.id FROM inventory_refreshes r
        WHERE r.status = 'queued'
          AND NOT EXISTS (
              SELECT 1 FROM inventory_refreshes busy
              WHERE busy.inventory_id = r.inventory_id AND busy.status = 'running')
        ORDER BY r.queued_at, r.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE inventory_refreshes SET
        status = 'running',
        claimed_at = now(),
        heartbeat_at = now(),
        lease_expires_at = now() + make_interval(secs => :lease),
        worker_id = :worker_id,
        claim_token_hash = :claim_hash,
        job_token_hash = :job_hash,
        job_token_expires_at = now() + make_interval(secs => :job_ttl)
    FROM candidate
    WHERE inventory_refreshes.id = candidate.id
    RETURNING inventory_refreshes.id
    """
)


@dataclass(frozen=True)
class Claim:
    """A claimed run, or (kind "refresh") a claimed inventory refresh with that id."""

    run_id: int
    claim_token: str
    job_token: str
    kind: str = "run"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def install_pending(db: Session) -> bool:
    return (
        db.scalar(select(GalaxyInstall.id).where(GalaxyInstall.status.in_(_ACTIVE)).limit(1))
        is not None
    )


def fail_run(run: Run, status: RunStatus, reason: str) -> None:
    """Ends a run for AnsiDeck's own reasons. The caller holds its row lock and commits."""
    run.status = status.value
    run.status_reason = reason[:500]
    run.finished_at = func.now()
    run.lease_expires_at = None
    run.claim_token_hash = None
    run.job_token_hash = None
    append_status_line(run, f"AnsiDeck: {reason}")
    if (session := object_session(run)) is not None:
        run_finished(session, run)
        metrics.run_finished(session, run.project_id, status.value, run.started_at)


def record_worker(db: Session, worker_id: str, slots: int, isolated: bool | None = None) -> None:
    """Marks the worker as seen now (the caller commits)."""
    stmt = insert(Worker).values(id=worker_id[:255], slots=slots, isolated=isolated)
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=[Worker.id],
            set_={
                "slots": stmt.excluded.slots,
                "isolated": stmt.excluded.isolated,
                "last_seen_at": func.now(),
            },
        )
    )
    # In a savepoint: notifications must never fail a claim or heartbeat.
    try:
        with db.begin_nested():
            worker_seen(db, worker_id, slots, isolated)
    except Exception:
        logger.exception("could not check worker %s for notifications", worker_id)


def online_slots(db: Session) -> int:
    """How many runs the workers seen lately can run at once (0: no worker is online)."""
    since = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, WORKER_ONLINE_SECONDS)
    return db.scalar(
        select(func.coalesce(func.sum(Worker.slots), 0)).where(Worker.last_seen_at > since)
    )


def wait_reason(db: Session, run: Run) -> str:
    """Why a queued run hasn't started yet, in the claim rules' order."""
    if install_pending(db):
        return "Waiting for a galaxy install to finish"
    if run.inventory_id is not None:
        # The run right ahead of it on the same inventory: the last earlier queued one, or else
        # the one running there now.
        ahead = db.scalar(
            select(Run.id)
            .where(
                Run.inventory_id == run.inventory_id,
                Run.status == RunStatus.QUEUED.value,
                tuple_(Run.queued_at, Run.id) < tuple_(run.queued_at, run.id),
            )
            .order_by(Run.queued_at.desc(), Run.id.desc())
            .limit(1)
        ) or db.scalar(
            select(Run.id).where(
                Run.inventory_id == run.inventory_id, Run.status == RunStatus.RUNNING.value
            )
        )
        if ahead is not None:
            return f"Waiting behind run #{ahead} (same inventory)"
    slots = online_slots(db)
    if slots == 0:
        return "No worker is online: start one to run queued runs"
    running = db.scalar(select(func.count()).where(Run.status == RunStatus.RUNNING.value))
    if running >= slots:
        return "Waiting for a free worker (all are busy)"
    return "Waiting for a worker…"


def claim_next(db: Session, worker_id: str, kinds: tuple[str, ...] = ("run",)) -> Claim | None:
    """Refreshes first (they are short, and someone may be waiting for the hosts), then runs.
    A worker that doesn't list "refresh" (from before 4G) never gets one."""
    if "refresh" in kinds and (claim := _claim_refresh(db, worker_id)) is not None:
        return claim
    if "run" not in kinds:
        return None
    return _claim_run(db, worker_id)


def _claim_refresh(db: Session, worker_id: str) -> Claim | None:
    for _ in range(_CLAIM_ATTEMPTS):
        claim_token, job_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        try:
            db.execute(text("SELECT pg_advisory_xact_lock_shared(:key)"), {"key": GALAXY_GATE_KEY})
            if install_pending(db):
                db.rollback()
                return None
            refresh_id = db.scalar(
                _CLAIM_REFRESH,
                {
                    "lease": get_settings().run_lease_seconds,
                    "worker_id": worker_id[:255],
                    "claim_hash": hash_token(claim_token),
                    "job_hash": hash_token(job_token),
                    "job_ttl": JOB_TOKEN_SECONDS,
                },
            )
        except IntegrityError as exc:
            db.rollback()
            if isinstance(exc.orig, UniqueViolation):
                continue
            raise
        if refresh_id is None:
            db.rollback()
            return None
        db.commit()
        return Claim(refresh_id, claim_token, job_token, kind="refresh")
    return None


def _claim_run(db: Session, worker_id: str) -> Claim | None:
    lease = get_settings().run_lease_seconds
    for _ in range(_CLAIM_ATTEMPTS):
        claim_token, job_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        try:
            db.execute(text("SELECT pg_advisory_xact_lock_shared(:key)"), {"key": GALAXY_GATE_KEY})
            if install_pending(db):
                db.rollback()
                return None
            run_id = db.scalar(
                _CLAIM,
                {
                    "lease": lease,
                    "worker_id": worker_id[:255],
                    "claim_hash": hash_token(claim_token),
                    "job_hash": hash_token(job_token),
                    "job_ttl": JOB_TOKEN_SECONDS,
                },
            )
        except IntegrityError as exc:
            db.rollback()
            if isinstance(exc.orig, UniqueViolation):
                continue  # lost a race for an inventory; the next candidate may be free
            raise
        if run_id is None:
            db.rollback()
            return None

        run = db.get(Run, run_id, populate_existing=True)
        reason = unrunnable_reason(run)
        if reason is None:
            waited = (run.claimed_at - run.queued_at).total_seconds()
            db.commit()
            metrics.run_claimed(waited)
            return Claim(run_id, claim_token, job_token)
        fail_run(run, RunStatus.FAILED, f"not run: {reason}")
        db.commit()
        notifier.notify(run_topic(run_id))
    return None
