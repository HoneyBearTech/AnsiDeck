"""The internal API workers talk to (and the only thing they can reach: workers have no
database access and no encryption key). A separate app on its own port, never published or
proxied; the public app has no /internal routes.

Every call carries the shared WORKER_TOKEN. After a claim, calls about a run also carry that
claim's token (X-Claim-Token); a worker whose claim ended (the reaper failed the run, say)
gets 410 Gone and must stop.
"""

import asyncio
import hashlib
import hmac
import logging
import threading
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit, metrics
from app.config import get_settings
from app.db import get_db, get_sessionmaker
from app.galaxy import try_start_install
from app.git_sync import snapshot_path
from app.hardening import FailureThrottle
from app.host_key_scans import MAX_RESULTS, build_scan_job, end_scan, scanned_keys
from app.host_key_store import record_learned, record_problems
from app.host_keys import MAX_LEARNED_LINES, MAX_PROBLEMS
from app.inventory_sources import (
    SourceError,
    build_refresh_job,
    end_refresh,
    normalise,
    store_snapshot,
)
from app.jobs import JobError, build_job
from app.lint import LintJobError, build_lint_job, end_lint
from app.models import GitSnapshot, HostKeyScan, InventoryRefresh, LintJob, Run, RunStatus
from app.notifications.events import run_finished
from app.notifications.ops import host_key_changed, secret_store_failed
from app.notify import notifier, run_topic
from app.queue import QUEUE_TOPIC, Claim, claim_next, fail_run, hash_token, record_worker
from app.run_log import append_events
from app.secret_store import OUTAGE_KINDS, SecretStoreError, explain
from app.storage import inventory_refresh_output_path, run_artifacts_path

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_CLAIM_WAIT_SECONDS = 25.0
_CLAIM_RECHECK_SECONDS = 2.0
# Set while the API shuts down: claim long polls answer "nothing to run" at once instead of
# holding the shutdown (and a dev server's reload) for up to MAX_CLAIM_WAIT_SECONDS.
_stopping = threading.Event()


def accept_long_polls() -> None:
    _stopping.clear()


def end_long_polls() -> None:
    _stopping.set()


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
    slots: int = Field(1, ge=1, le=256)
    isolated: bool | None = None  # None: a worker from before Phase 4C
    egress_filtered: bool | None = None  # None: a worker from before its egress filter
    wait_seconds: float = Field(MAX_CLAIM_WAIT_SECONDS, ge=0, le=MAX_CLAIM_WAIT_SECONDS)
    # What the worker can do; one from before 4G (no kinds) is only ever given runs.
    kinds: list[Literal["run", "refresh", "lint", "keyscan"]] = Field(
        ["run"], min_length=1, max_length=4
    )
    # It checks SSH host keys (app.host_keys); one that doesn't never gets a run that must.
    host_keys: bool = False


class ClaimOut(BaseModel):
    # "refresh" / "lint" / "keyscan": run_id is an inventory refresh's, a playbook check's or a
    # host key scan's id.
    kind: Literal["run", "refresh", "lint", "keyscan"] = "run"
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


class HeartbeatRefresh(BaseModel):
    refresh_id: int
    claim_token: str = Field(max_length=200)


class HeartbeatKeyscan(BaseModel):
    scan_id: int
    claim_token: str = Field(max_length=200)


class HeartbeatLint(BaseModel):
    lint_id: int
    claim_token: str = Field(max_length=200)


class HeartbeatIn(BaseModel):
    worker_id: str = Field(min_length=1, max_length=255)
    slots: int = Field(1, ge=1, le=256)
    isolated: bool | None = None
    egress_filtered: bool | None = None
    host_keys: bool = False
    runs: list[HeartbeatRun] = Field(max_length=256)
    refreshes: list[HeartbeatRefresh] = Field([], max_length=256)
    lints: list[HeartbeatLint] = Field([], max_length=256)
    keyscans: list[HeartbeatKeyscan] = Field([], max_length=256)


class FindingIn(BaseModel):
    rule: str = Field(max_length=100)
    level: Literal["error", "warning"]
    message: str = Field(max_length=500)
    details: str | None = Field(None, max_length=2000)
    path: str = Field(max_length=1024)
    line: int = Field(ge=1, le=10_000_000)
    column: int | None = Field(None, ge=0, le=10_000_000)
    url: str | None = Field(None, max_length=300, pattern=r"^https://")


class KeyscanCompleteIn(BaseModel):
    status: Literal["success", "failed", "timed_out"]
    # ssh-keyscan's output lines (untrusted: only keys for the scan's own targets are kept).
    lines: list[Annotated[str, Field(max_length=20_000)]] = Field([], max_length=MAX_RESULTS)
    error: str | None = Field(None, max_length=1000)


class LintCompleteIn(BaseModel):
    status: Literal["success", "failed", "timed_out"]
    findings: list[FindingIn] = Field([], max_length=500)
    total: int = Field(0, ge=0)
    truncated: bool = False
    external: int = Field(0, ge=0)
    repo_config: bool = False
    error: str | None = Field(None, max_length=1000)
    # The worker redacted a secret's value somewhere in the findings.
    scrubbed: bool = False
    version: str | None = Field(None, max_length=40)


class RefreshCompleteIn(BaseModel):
    status: Literal["success", "failed", "timed_out"]
    bytes: int = Field(0, ge=0)
    sha256: str | None = Field(None, max_length=64)
    error: str | None = Field(None, max_length=1000)
    # The worker redacted a credential's value somewhere in the output.
    scrubbed: bool = False


class HostKeyProblemIn(BaseModel):
    host: str = Field(max_length=255)
    problem: Literal["changed", "unknown", "failed"]
    name: str | None = Field(None, max_length=300)
    key_type: str | None = Field(None, max_length=64)
    presented: str | None = Field(None, max_length=64, pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")


class ArtifactFile(BaseModel):
    path: str = Field(max_length=1024)
    size: int = Field(ge=0)


class ArtifactsIn(BaseModel):
    """The run's artifacts as uploaded (POST /runs/{id}/artifacts), or why they weren't kept."""

    files: list[ArtifactFile] = Field([], max_length=100_000)
    bytes: int = Field(0, ge=0)
    tar_bytes: int = Field(0, ge=0)
    sha256: str | None = Field(None, max_length=64)
    error: str | None = Field(None, max_length=300)


class CompleteIn(BaseModel):
    last_seq: int = Field(ge=0)
    status: Literal["success", "failed", "cancelled", "timed_out"]
    return_code: int | None = None
    reason: str | None = Field(None, max_length=500)
    host_counts: dict[str, int] | None = None
    # Keys the run's ssh learned (accept_new), as known_hosts lines: untrusted, the playbook
    # can write the file they come from (app.host_key_store.record_learned filters them).
    learned_host_keys: list[Annotated[str, Field(max_length=20_000)]] | None = Field(
        None, max_length=MAX_LEARNED_LINES
    )
    host_key_problems: list[HostKeyProblemIn] | None = Field(None, max_length=MAX_PROBLEMS)
    artifacts: ArtifactsIn | None = None


@router.post("/ping")
def ping() -> dict[str, bool]:
    return {"ok": True}


def _claim_once(
    worker_id: str, kinds: tuple[str, ...] = ("run",), host_keys: bool = False
) -> Claim | None:
    db = get_sessionmaker()()
    try:
        return claim_next(db, worker_id, kinds, host_keys)
    finally:
        db.close()


def _seen(body: ClaimIn) -> None:
    db = get_sessionmaker()()
    try:
        record_worker(
            db, body.worker_id, body.slots, body.isolated, body.egress_filtered, body.host_keys
        )
        db.commit()
    finally:
        db.close()


@router.post("/claim", response_model=ClaimOut, responses={204: {"description": "Nothing to run"}})
async def claim(body: ClaimIn) -> ClaimOut | Response:
    """Long poll: returns as soon as a run can be claimed, or 204 after wait_seconds."""
    await asyncio.to_thread(_seen, body)
    # A production worker refuses to start without isolation; this covers one started without
    # ENVIRONMENT=production (or from before 4C): it stays visible, and alerts, but gets no work.
    if body.isolated is not True and get_settings().environment.lower() == "production":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this API hands work only to workers that isolate runs (ENVIRONMENT=production)",
        )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + body.wait_seconds
    with notifier.listen(QUEUE_TOPIC) as listener:
        while True:
            claimed = await asyncio.to_thread(
                _claim_once, body.worker_id, tuple(body.kinds), body.host_keys
            )
            if claimed is not None:
                return ClaimOut(
                    kind=claimed.kind,
                    run_id=claimed.run_id,
                    claim_token=claimed.claim_token,
                    job_token=claimed.job_token,
                )
            remaining = deadline - loop.time()
            if remaining <= 0 or _stopping.is_set():
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
    except SecretStoreError as exc:
        label = get_settings().secrets_store_label
        subject = getattr(exc, "subject", "a secret")
        fail_run(
            run,
            RunStatus.FAILED,
            f"not run: could not read {subject} from {label}: {explain(exc.kind)}",
        )
        if exc.kind in OUTAGE_KINDS:
            try:
                with db.begin_nested():
                    secret_store_failed(db, exc.kind, label)
            except Exception:  # the run's failure is what matters
                logger.exception("could not raise the secret store alert")
        db.commit()
        _finished(run_id)
        return _gone()
    except JobError as exc:
        fail_run(run, RunStatus.FAILED, f"not run: {exc}")
        db.commit()
        _finished(run_id)
        return _gone()
    except Exception:  # never echo details that might hold secrets
        logger.exception("could not build the job for run %s", run_id)
        fail_run(run, RunStatus.FAILED, "could not prepare the job (see the server log)")
        db.commit()
        _finished(run_id)
        return _gone()
    run.started_at = func.now()  # the worker launches ansible next
    db.commit()
    return payload


@router.post("/runs/{run_id}/snapshot")
def snapshot(
    run_id: int,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """The repository snapshot (a tar) a run of a synced playbook executes in. Its path comes
    from the run's row; the worker checks size and hash against its job."""
    run = _locked_run(db, run_id, x_claim_token)
    if run is None:
        return _gone()
    return _snapshot_file(db, run.git_snapshot_id)


def _snapshot_file(db: Session, snapshot_id: int | None) -> Any:
    """A repository snapshot's tar (its path comes from the job's row, never the request)."""
    snapshot_row = db.get(GitSnapshot, snapshot_id) if snapshot_id else None
    db.commit()
    if snapshot_row is None:
        return JSONResponse({"detail": "This job has no repository snapshot"}, 404)
    path = snapshot_path(snapshot_row)
    if not path.is_file():
        return JSONResponse({"detail": "The repository snapshot is gone"}, 404)
    return FileResponse(path, media_type="application/x-tar")


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
    record_worker(
        db, body.worker_id, body.slots, body.isolated, body.egress_filtered, body.host_keys
    )
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
    refreshes: list[dict] = []
    for item in body.refreshes:
        renewed = db.execute(
            update(InventoryRefresh)
            .where(
                InventoryRefresh.id == item.refresh_id,
                InventoryRefresh.status == RunStatus.RUNNING.value,
                InventoryRefresh.claim_token_hash == hash_token(item.claim_token),
            )
            .values(
                heartbeat_at=func.now(),
                lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease),
            )
            .returning(InventoryRefresh.id)
        ).first()
        refreshes.append(
            {"refresh_id": item.refresh_id, "state": "ok" if renewed is not None else "gone"}
        )
    lints: list[dict] = []
    for item in body.lints:
        renewed = db.execute(
            update(LintJob)
            .where(
                LintJob.id == item.lint_id,
                LintJob.status == RunStatus.RUNNING.value,
                LintJob.claim_token_hash == hash_token(item.claim_token),
            )
            .values(
                heartbeat_at=func.now(),
                lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease),
            )
            .returning(LintJob.id)
        ).first()
        lints.append({"lint_id": item.lint_id, "state": "ok" if renewed is not None else "gone"})
    keyscans: list[dict] = []
    for item in body.keyscans:
        renewed = db.execute(
            update(HostKeyScan)
            .where(
                HostKeyScan.id == item.scan_id,
                HostKeyScan.status == RunStatus.RUNNING.value,
                HostKeyScan.claim_token_hash == hash_token(item.claim_token),
            )
            .values(
                heartbeat_at=func.now(),
                lease_expires_at=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lease),
            )
            .returning(HostKeyScan.id)
        ).first()
        keyscans.append({"scan_id": item.scan_id, "state": "ok" if renewed is not None else "gone"})
    db.commit()
    return {"runs": answers, "refreshes": refreshes, "lints": lints, "keyscans": keyscans}


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
    learned, problems = _host_keys(db, run, body)
    if body.artifacts is not None:
        _keep_artifacts(run, body.artifacts)
    run_finished(db, run)
    metrics.run_finished(db, project_id, body.status, run.started_at)
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
    _audit_host_keys(db, run_id, project_id, learned, problems)
    _finished(run_id)
    return {}


def _artifacts_part(run_id: int) -> Path:
    return run_artifacts_path(run_id).with_suffix(".part")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _keep_artifacts(run: Run, artifacts: ArtifactsIn) -> None:
    """Makes the uploaded tar the run's artifacts if it is what the worker says it is (and
    within this API's limits), else records why it wasn't kept."""
    settings = get_settings()
    part, error = _artifacts_part(run.id), artifacts.error
    if error is None:
        size = part.stat().st_size if part.exists() else -1
        digest = _sha256_file(part) if size >= 0 else None
        if size != artifacts.tar_bytes or digest != artifacts.sha256:
            error = "the artifacts didn't arrive intact"
        elif len(artifacts.files) > settings.run_artifact_max_files or (
            artifacts.bytes > settings.run_artifact_max_mb * 1024 * 1024
        ):
            error = "the artifacts are over this server's limits"
    if error is not None:
        part.unlink(missing_ok=True)
        run.artifacts_error = error[:300]
        return
    part.replace(run_artifacts_path(run.id))
    run.artifacts_files = [f.model_dump() for f in artifacts.files]
    run.artifacts_bytes = artifacts.bytes
    run.artifacts_tar_bytes = artifacts.tar_bytes
    run.artifacts_sha256 = artifacts.sha256


@router.post("/runs/{run_id}/artifacts")
async def run_artifacts(
    run_id: int,
    request: Request,
    x_claim_token: str = Header(max_length=200),
    x_offset: int = Header(ge=0),
) -> Any:
    """Appends a chunk of the run's artifacts tar at X-Offset (a resent chunk is accepted
    again; a gap is refused with the offset to resend from)."""
    chunk = await request.body()
    return await asyncio.to_thread(_append_artifacts, run_id, x_claim_token, x_offset, chunk)


def _append_artifacts(run_id: int, claim_token: str, offset: int, chunk: bytes) -> Any:
    db = get_sessionmaker()()
    try:
        run = _locked_run(db, run_id, claim_token)
        if run is None:
            return _gone()
        path = _artifacts_part(run.id)  # the row's id, not the request's
        size = path.stat().st_size if path.exists() else 0
        if offset > size:
            return JSONResponse({"expected_offset": size}, status.HTTP_409_CONFLICT)
        # A tar can be a little larger than its files, never twice their size.
        if offset + len(chunk) > get_settings().run_artifact_max_mb * 2 * 1024 * 1024 + 2**20:
            return JSONResponse({"detail": "The artifacts are too large"}, 413)
        with open(path, "r+b" if path.exists() else "wb") as staged:
            staged.seek(offset)
            staged.write(chunk)
            staged.truncate()
        db.commit()
        return {"offset": offset + len(chunk)}
    finally:
        db.close()


def _host_keys(db: Session, run: Run, body: CompleteIn) -> tuple[list[dict], list[dict]]:
    """Keeps the keys the run learned and what ssh refused, in a savepoint: bad data must
    never keep a run from finishing. Returns them for the audit log and notifications."""
    problems = [p.model_dump() for p in body.host_key_problems or []]
    learned: list[dict] = []
    inventory_id, inventory_name = run.inventory_id, run.inventory_name
    try:
        with db.begin_nested():
            learned = record_learned(db, run, body.learned_host_keys or [])
            record_problems(run, problems)
            changed = [p for p in problems if p["problem"] == "changed"]
            if changed and inventory_id is not None:
                host_key_changed(db, run, changed)
    except Exception:
        logger.exception("could not record run %s's host keys", run.id)
        learned = []
    return (
        [{**k, "inventory_id": inventory_id, "inventory": inventory_name} for k in learned],
        [{**p, "inventory_id": inventory_id, "inventory": inventory_name} for p in problems],
    )


def _audit_host_keys(
    db: Session, run_id: int, project_id: int, learned: list[dict], problems: list[dict]
) -> None:
    for action, items, outcome in (
        ("inventory.host_key_learned", learned, "success"),
        ("inventory.host_key_refused", problems, "failure"),
    ):
        if not items:
            continue
        audit.record(
            db,
            action,
            outcome=outcome,
            actor_username=f"run #{run_id}",
            target_type="inventory",
            target_id=items[0]["inventory_id"],
            target_name=items[0]["inventory"],
            project_id=project_id,
            detail={
                "run_id": run_id,
                "keys": [
                    {k: v for k, v in item.items() if k not in ("inventory_id", "inventory")}
                    for item in items[:20]
                ],
                "count": len(items),
            },
        )


# --- inventory refreshes (Phase 4G) -------------------------------------------------------


def _locked_refresh(db: Session, refresh_id: int, claim_token: str) -> InventoryRefresh | None:
    """The refresh, row-locked, if this claim still owns it."""
    refresh = db.scalars(
        select(InventoryRefresh).where(InventoryRefresh.id == refresh_id).with_for_update()
    ).first()
    if (
        refresh is None
        or refresh.status != RunStatus.RUNNING.value
        or refresh.claim_token_hash is None
        or not hmac.compare_digest(refresh.claim_token_hash, hash_token(claim_token))
    ):
        return None
    return refresh


def _end_refresh(db: Session, refresh: InventoryRefresh, status: str, error: str | None) -> None:
    """Ends it, commits, records a new failure streak and frees what waited for it."""
    refresh_id = refresh.id
    pending_audit = end_refresh(db, refresh, status, error)
    db.commit()
    inventory_refresh_output_path(refresh_id).unlink(missing_ok=True)
    if pending_audit:
        audit.record(db, **pending_audit)
    notifier.notify(QUEUE_TOPIC)
    try_start_install()


@router.post("/refreshes/{refresh_id}/job")
def refresh_job(
    refresh_id: int,
    body: JobIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Hands the refresh job (with its credentials' variables) out exactly once."""
    refresh = _locked_refresh(db, refresh_id, x_claim_token)
    if (
        refresh is None
        or refresh.job_token_hash is None
        or not hmac.compare_digest(refresh.job_token_hash, hash_token(body.job_token))
        or refresh.job_token_expires_at <= db.scalar(select(func.now()))
    ):
        return _gone()
    refresh.job_token_hash = None
    refresh.job_token_expires_at = None
    try:
        payload = build_refresh_job(db, refresh)
    except SecretStoreError as exc:
        label = get_settings().secrets_store_label
        subject = getattr(exc, "subject", "a secret")
        if exc.kind in OUTAGE_KINDS:
            try:
                with db.begin_nested():
                    secret_store_failed(db, exc.kind, label)
            except Exception:  # the refresh's failure is what matters
                logger.exception("could not raise the secret store alert")
        _end_refresh(
            db,
            refresh,
            RunStatus.FAILED.value,
            f"could not read {subject} from {label}: {explain(exc.kind)}",
        )
        return _gone()
    except SourceError as exc:
        _end_refresh(db, refresh, RunStatus.FAILED.value, str(exc))
        return _gone()
    except Exception:  # never echo details that might hold secrets
        logger.exception("could not build the job for refresh %s", refresh_id)
        _end_refresh(
            db,
            refresh,
            RunStatus.FAILED.value,
            "could not prepare the refresh (see the server log)",
        )
        return _gone()
    refresh.started_at = func.now()
    db.commit()
    return payload


@router.post("/refreshes/{refresh_id}/output")
async def refresh_output(
    refresh_id: int,
    request: Request,
    x_claim_token: str = Header(max_length=200),
    x_offset: int = Header(ge=0),
) -> Any:
    """Appends a chunk of the refresh's output at X-Offset (a resent chunk is accepted again;
    a gap is refused with the offset to resend from)."""
    chunk = await request.body()
    return await asyncio.to_thread(_append_output, refresh_id, x_claim_token, x_offset, chunk)


def _append_output(refresh_id: int, claim_token: str, offset: int, chunk: bytes) -> Any:
    db = get_sessionmaker()()
    try:
        refresh = _locked_refresh(db, refresh_id, claim_token)
        if refresh is None:
            return _gone()
        path = inventory_refresh_output_path(refresh.id)  # the row's id, not the request's
        size = path.stat().st_size if path.exists() else 0
        if offset > size:
            return JSONResponse({"expected_offset": size}, status.HTTP_409_CONFLICT)
        limit = get_settings().inventory_max_output_mb * 1024 * 1024
        if offset + len(chunk) > limit:
            return JSONResponse({"detail": "The output is too large"}, 413)
        with open(path, "r+b" if path.exists() else "wb") as staged:
            staged.seek(offset)
            staged.write(chunk)
            staged.truncate()
        db.commit()
        return {"offset": offset + len(chunk)}
    finally:
        db.close()


@router.post("/refreshes/{refresh_id}/complete")
def refresh_complete(
    refresh_id: int,
    body: RefreshCompleteIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Checks the uploaded output against the worker's size and hash, normalises it and makes
    it the inventory's current snapshot, or records why the refresh failed."""
    refresh = _locked_refresh(db, refresh_id, x_claim_token)
    if refresh is None:
        return _gone()
    if body.status != RunStatus.SUCCESS.value:
        _end_refresh(db, refresh, body.status, body.error or body.status.replace("_", " "))
        return {}
    path = inventory_refresh_output_path(refresh.id)  # the row's id, not the request's
    raw = path.read_bytes() if path.exists() else b""
    if len(raw) != body.bytes or hashlib.sha256(raw).hexdigest() != body.sha256:
        return JSONResponse({"detail": "The output doesn't match its size and hash"}, 409)
    try:
        snapshot, warnings = normalise(raw, (refresh.sources or {}).get("static_hosts", []))
    except SourceError as exc:
        _end_refresh(db, refresh, RunStatus.FAILED.value, str(exc))
        return {}
    if body.scrubbed:
        warnings.insert(0, "a credential's value appeared in the output and was redacted")
    refresh.output_bytes = len(raw)
    store_snapshot(db, refresh, snapshot, warnings)
    _end_refresh(db, refresh, RunStatus.SUCCESS.value, None)
    return {}


# --- playbook checks (Phase 5B) ------------------------------------------------------------


def _locked_lint(db: Session, lint_id: int, claim_token: str) -> LintJob | None:
    """The check, row-locked, if this claim still owns it."""
    lint = db.scalars(select(LintJob).where(LintJob.id == lint_id).with_for_update()).first()
    if (
        lint is None
        or lint.status != RunStatus.RUNNING.value
        or lint.claim_token_hash is None
        or not hmac.compare_digest(lint.claim_token_hash, hash_token(claim_token))
    ):
        return None
    return lint


def _end_lint(
    db: Session, lint: LintJob, status: str, error: str | None, result: dict | None = None
) -> None:
    end_lint(lint, status, error=error, result=result)
    db.commit()
    notifier.notify(QUEUE_TOPIC)  # the next check may start, and a waiting install
    try_start_install()


@router.post("/lints/{lint_id}/job")
def lint_job(
    lint_id: int,
    body: JobIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Hands the check's job out exactly once."""
    lint = _locked_lint(db, lint_id, x_claim_token)
    if (
        lint is None
        or lint.job_token_hash is None
        or not hmac.compare_digest(lint.job_token_hash, hash_token(body.job_token))
        or lint.job_token_expires_at <= db.scalar(select(func.now()))
    ):
        return _gone()
    lint.job_token_hash = None
    lint.job_token_expires_at = None
    try:
        payload = build_lint_job(db, lint)
    except LintJobError as exc:
        _end_lint(db, lint, RunStatus.FAILED.value, str(exc))
        return _gone()
    except Exception:  # never echo details
        logger.exception("could not build the job for check %s", lint_id)
        _end_lint(
            db, lint, RunStatus.FAILED.value, "could not prepare the check (see the server log)"
        )
        return _gone()
    lint.started_at = func.now()
    db.commit()
    return payload


@router.post("/lints/{lint_id}/snapshot")
def lint_snapshot(
    lint_id: int,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """The repository a check of a synced playbook runs in (checked by size and hash)."""
    lint = _locked_lint(db, lint_id, x_claim_token)
    if lint is None:
        return _gone()
    return _snapshot_file(db, lint.git_snapshot_id)


@router.post("/lints/{lint_id}/complete")
def lint_complete(
    lint_id: int,
    body: LintCompleteIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Records the findings, or why the check failed."""
    lint = _locked_lint(db, lint_id, x_claim_token)
    if lint is None:
        return _gone()
    if body.status != RunStatus.SUCCESS.value:
        _end_lint(db, lint, body.status, body.error or body.status.replace("_", " "))
        return {}
    result = {
        "findings": [finding.model_dump() for finding in body.findings],
        "total": max(body.total, len(body.findings)),
        "truncated": body.truncated,
        "external": body.external,
        "repo_config": body.repo_config,
        "scrubbed": body.scrubbed,
        "version": body.version,
    }
    _end_lint(db, lint, RunStatus.SUCCESS.value, None, result)
    return {}


internal_app = FastAPI(
    title="AnsiDeck internal worker API", docs_url=None, redoc_url=None, openapi_url=None
)
internal_app.include_router(router)
internal_app.add_middleware(WorkerAuthMiddleware)
internal_app.add_middleware(metrics.HTTPMetricsMiddleware, server="internal")  # outermost


# --- host key scans -----------------------------------------------------------------------


def _locked_scan(db: Session, scan_id: int, claim_token: str) -> HostKeyScan | None:
    """The scan, row-locked, if this claim still owns it."""
    scan = db.scalars(
        select(HostKeyScan).where(HostKeyScan.id == scan_id).with_for_update()
    ).first()
    if (
        scan is None
        or scan.status != RunStatus.RUNNING.value
        or scan.claim_token_hash is None
        or not hmac.compare_digest(scan.claim_token_hash, hash_token(claim_token))
    ):
        return None
    return scan


def _end_scan(
    db: Session, scan: HostKeyScan, status: str, error: str | None, results: list | None = None
) -> None:
    end_scan(scan, status, error=error, results=results)
    db.commit()
    notifier.notify(QUEUE_TOPIC)  # the inventory's next scan may start


@router.post("/keyscans/{scan_id}/job")
def keyscan_job(
    scan_id: int,
    body: JobIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Hands the scan's job (its targets) out exactly once."""
    scan = _locked_scan(db, scan_id, x_claim_token)
    if (
        scan is None
        or scan.job_token_hash is None
        or not hmac.compare_digest(scan.job_token_hash, hash_token(body.job_token))
        or scan.job_token_expires_at <= db.scalar(select(func.now()))
    ):
        return _gone()
    scan.job_token_hash = None
    scan.job_token_expires_at = None
    scan.started_at = func.now()
    payload = build_scan_job(scan)
    db.commit()
    return payload


@router.post("/keyscans/{scan_id}/complete")
def keyscan_complete(
    scan_id: int,
    body: KeyscanCompleteIn,
    x_claim_token: str = Header(max_length=200),
    db: Session = Depends(get_db),
) -> Any:
    """Records the keys the targets presented, or why the scan failed."""
    scan = _locked_scan(db, scan_id, x_claim_token)
    if scan is None:
        return _gone()
    if body.status != RunStatus.SUCCESS.value:
        _end_scan(db, scan, body.status, body.error or body.status.replace("_", " "))
        return {}
    results = scanned_keys(scan, body.lines)
    error = None
    if not results:
        error = body.error or "no host answered with a key"
    _end_scan(db, scan, RunStatus.SUCCESS.value, error, results)
    return {}
