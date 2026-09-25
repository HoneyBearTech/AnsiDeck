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
import secrets
from dataclasses import dataclass

from psycopg.errors import UniqueViolation
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import GALAXY_GATE_KEY
from app.jobs import unrunnable_reason
from app.models import GalaxyInstall, Run, RunStatus
from app.notify import notifier, run_topic
from app.run_log import append_status_line

QUEUE_TOPIC = "queue"
JOB_TOKEN_SECONDS = 60
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


@dataclass(frozen=True)
class Claim:
    run_id: int
    claim_token: str
    job_token: str


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


def claim_next(db: Session, worker_id: str) -> Claim | None:
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
            db.commit()
            return Claim(run_id, claim_token, job_token)
        fail_run(run, RunStatus.FAILED, f"not run: {reason}")
        db.commit()
        notifier.notify(run_topic(run_id))
    return None
