"""The internal API workers talk to (and the only thing they can reach: workers have no
database access and no encryption key). A separate app on its own port, never published or
proxied; the public app has no /internal routes.

Every call carries the shared WORKER_TOKEN. After a claim, calls about a run also carry that
claim's token (X-Claim-Token); a worker whose claim ended (the reaper failed the run, say)
gets 410 Gone and must stop.
"""

import asyncio
import hmac
import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import get_db, get_sessionmaker
from app.galaxy import try_start_install
from app.hardening import FailureThrottle
from app.jobs import build_job
from app.models import Run, RunStatus
from app.notify import notifier, run_topic
from app.queue import QUEUE_TOPIC, Claim, claim_next, fail_run, hash_token
from app.run_log import append_events

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_CLAIM_WAIT_SECONDS = 25.0
_CLAIM_RECHECK_SECONDS = 2.0
_HOST_COUNT_COLUMNS = (
    "hosts_total",
    "hosts_ok",
    "hosts_changed",
    "hosts_failed",
    "hosts_unreachable",
)

worker_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)


def _gone() -> JSONResponse:
    return JSONResponse({"detail": "This claim is no longer valid"}, status.HTTP_410_GONE)


def _behind(expected_seq: int) -> JSONResponse:
    return JSONResponse({"expected_seq": expected_seq}, status.HTTP_409_CONFLICT)


class WorkerAuthMiddleware:
    """Pure ASGI, so it runs before any routing or body parsing."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = (scope.get("client") or ("", 0))[0]
        headers = dict(scope["headers"])

        async def reject(code: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, code)(scope, receive, send)

        if worker_ip_throttle.blocked(ip):
            await reject(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
            return
        expected = f"Bearer {get_settings().worker_token}".encode()
        if not hmac.compare_digest(headers.get(b"authorization", b""), expected):
            worker_ip_throttle.record_failure(ip)
            await asyncio.to_thread(_audit_auth_failure, ip)
            await reject(status.HTTP_401_UNAUTHORIZED, "Invalid worker token")
            return

        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = MAX_BODY_BYTES + 1
        if declared > MAX_BODY_BYTES:
            await reject(status.HTTP_413_CONTENT_TOO_LARGE, "Request body too large")
            return

        received = 0

        async def capped_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > MAX_BODY_BYTES:
                raise ValueError("request body exceeds the internal API limit")
            return message

        await self.app(scope, capped_receive, send)


def _audit_auth_failure(ip: str) -> None:
    db = get_sessionmaker()()
    try:
        audit.record(db, "worker.auth_failed", outcome="failure", target_type="worker", ip=ip)
    finally:
        db.close()


router = APIRouter(prefix="/internal")


class ClaimIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=255)
    wait_seconds: float = Field(MAX_CLAIM_WAIT_SECONDS, ge=0, le=MAX_CLAIM_WAIT_SECONDS)


class ClaimOut(BaseModel):
    run_id: int
    claim_token: str
    job_token: str


class JobIn(BaseModel):
    job_token: str = Field(max_length=200)


class EventsIn(BaseModel):
    first_seq: int = Field(ge=1)
    events: list[dict[str, Any]] = Field(max_length=10_000)


class HeartbeatRun(BaseModel):
    run_id: int
    claim_token: str = Field(max_length=200)


class HeartbeatIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=255)
    runs: list[HeartbeatRun] = Field(max_length=256)


class CompleteIn(BaseModel):
    last_seq: int = Field(ge=0)
    status: Literal["success", "failed", "cancelled", "timed_out"]
    return_code: int | None = None
    reason: str | None = Field(None, max_length=500)
    host_counts: dict[str, int] | None = None


@router.post("/ping")
def ping() -> dict[str, bool]:
    return {"ok": True}


def _claim_once(worker_id: str) -> Claim | None:
    db = get_sessionmaker()()
    try:
        return claim_next(db, worker_id)
    finally:
        db.close()


@router.post("/claim", response_model=ClaimOut, responses={204: {"description": "Nothing to run"}})
async def claim(body: ClaimIn) -> ClaimOut | Response:
    """Long poll: returns as soon as a run can be claimed, or 204 after wait_seconds."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + body.wait_seconds
    with notifier.listen(QUEUE_TOPIC) as listener:
        while True:
            claimed = await asyncio.to_thread(_claim_once, body.worker_id)
            if claimed is not None:
                return ClaimOut(
                    run_id=claimed.run_id,
                    claim_token=claimed.claim_token,
                    job_token=claimed.job_token,
                )
            remaining = deadline - loop.time()
            if remaining <= 0:
                return Response(status_code=status.HTTP_204_NO_CONTENT)
            await listener.wait(min(_CLAIM_RECHECK_SECONDS, remaining))


def _locked_run(db: Session, run_id: int, claim_token: str) -> Run | None:
    """The run, row-locked, if this claim still owns it."""
    run = db.scalars(select(Run).where(Run.id == run_id).with_for_update()).first()
    if (
        run is None
        or run.status != RunStatus.RUNNING.value
        or run.claim_token_hash is None
        or not hmac.compare_digest(run.claim_token_hash, hash_token(claim_token))
    ):
        return None
    return run


def _finished(run_id: int) -> None:
    """After a run ended: wake its viewers and the claimers (its inventory is free), and let a
    waiting galaxy install start if this was the last running run."""
    notifier.notify(run_topic(run_id))
    notifier.notify(QUEUE_TOPIC)
    try_start_install()


@router.post("/runs/{run_id}/job")
def job(
    run_id: int,
    body: JobIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Hands the job (with its decrypted secrets) out exactly once."""
    run = _locked_run(db, run_id, x_claim_token)
    if (
        run is None
        or run.job_token_hash is None
        or not hmac.compare_digest(run.job_token_hash, hash_token(body.job_token))
        or run.job_token_expires_at <= db.scalar(select(func.now()))
    ):
        return _gone()
    run.job_token_hash = None
    run.job_token_expires_at = None
    if run.cancel_requested_at is not None:
        fail_run(run, RunStatus.CANCELLED, "cancelled before it started")
        db.commit()
        _finished(run_id)
        return _gone()
    try:
        payload = build_job(db, run)
    except Exception:  # noqa: BLE001 - never echo details that might hold secrets
        logger.exception("could not build the job for run %s", run_id)
        fail_run(run, RunStatus.FAILED, "could not prepare the job (see the server log)")
        db.commit()
        _finished(run_id)
        return _gone()
    run.started_at = func.now()  # the worker launches ansible next
    db.commit()
    return payload


@router.post("/runs/{run_id}/events")
def events(
    run_id: int,
    body: EventsIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Appends a batch of (already scrubbed) events. Sequence numbers make retries safe:
    events up to runs.log_seq are skipped, and a gap is refused with the seq to resend from."""
    run = _locked_run(db, run_id, x_claim_token)
    if run is None:
        return _gone()
    expected = run.log_seq + 1
    if body.first_seq > expected:
        return _behind(expected)
    fresh = body.events[expected - body.first_seq :]
    if fresh:
        append_events(run, fresh)
        run.log_seq = body.first_seq + len(body.events) - 1
    acked, cancel = run.log_seq, run.cancel_requested_at is not None
    db.commit()
    if fresh:
        notifier.notify(run_topic(run_id))
    return {"acked_seq": acked, "cancel": cancel}


@router.post("/heartbeat")
def heartbeat(body: HeartbeatIn, db: Session = Depends(get_db)) -> dict[str, list[dict]]:
    """Renews the lease of each run the worker still owns: "ok", "cancel" (stop it), or "gone"
    (the claim ended; stop without reporting)."""
    lease = get_settings().run_lease_seconds
    answers: list[dict] = []
    for item in body.runs:
        row = db.execute(
            update(Run)
            .where(
                Run.id == item.run_id,
                Run.status == RunStatus.RUNNING.value,
                Run.claim_token_hash == hash_token(item.claim_token),
            )
            .values(
                heartbeat_at=func.now(),
                lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease),
            )
            .returning(Run.cancel_requested_at)
        ).first()
        state = "gone" if row is None else ("cancel" if row[0] else "ok")
        answers.append({"run_id": item.run_id, "state": state})
    db.commit()
    return {"runs": answers}


@router.post("/runs/{run_id}/complete")
def complete(
    run_id: int,
    body: CompleteIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Records the outcome, but only once every event is in the log (so a finished run's
    output is complete by definition)."""
    run = _locked_run(db, run_id, x_claim_token)
    if run is None:
        return _gone()
    if body.last_seq != run.log_seq:
        return _behind(run.log_seq + 1)

    reason = body.reason
    if body.status == RunStatus.CANCELLED and run.cancel_requested_by:
        reason = f"cancelled by {run.cancel_requested_by}"
    run.status = body.status
    run.status_reason = reason
    run.return_code = body.return_code
    for column in _HOST_COUNT_COLUMNS:
        if body.host_counts and column in body.host_counts:
            setattr(run, column, body.host_counts[column])
    run.finished_at = func.now()
    run.lease_expires_at = None
    run.claim_token_hash = None
    project_id, worker_id = run.project_id, run.worker_id
    db.commit()

    if body.status == RunStatus.TIMED_OUT:
        audit.record(
            db,
            "run.timed_out",
            outcome="failure",
            actor_username=worker_id,
            target_type="run",
            target_id=run_id,
            project_id=project_id,
        )
    _finished(run_id)
    return {}


internal_app = FastAPI(
    title="AnsiDeck internal worker API", docs_url=None, redoc_url=None, openapi_url=None
)
internal_app.include_router(router)
internal_app.add_middleware(WorkerAuthMiddleware)
