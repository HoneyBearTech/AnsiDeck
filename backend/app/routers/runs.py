import asyncio
import contextlib
import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, git_sync, metrics
from app.db import get_db, get_sessionmaker
from app.dependencies import SESSION_COOKIE_NAME, RateLimited, authenticate_request
from app.hardening import client_ip
from app.inventory_render import merge, static_data, static_problems
from app.inventory_sources import has_sources
from app.models import (
    FINISHED_STATUSES,
    MAX_RUN_TIMEOUT_SECONDS,
    Credential,
    GitSnapshot,
    GitSource,
    Inventory,
    InventoryGroup,
    InventorySnapshot,
    Playbook,
    Run,
    RunStatus,
    User,
    VaultPassword,
)
from app.notify import notifier, run_topic
from app.permissions import (
    Permission,
    Scope,
    guard,
    holds_somewhere,
    project_permissions,
)
from app.queue import QUEUE_TOPIC, fail_run, wait_reason
from app.schemas.runs import RunCreate, RunOut
from app.scoping import get_scoped, readable_project_ids
from app.storage import playbook_path, run_log_path

router = APIRouter()

MAX_PLAYBOOK_SNAPSHOT_BYTES = 1024 * 1024
# The inventory's own hosts and groups, pinned on each run.
MAX_INVENTORY_PIN_BYTES = 4 * 1024 * 1024


# The only routes an API key may reach (a test pins this set).
_guard = guard(Permission.CONTENT_READ, Permission.RUNS_TRIGGER, scope=Scope.PROJECT, api_key=True)
# People only: a key starts runs from explicit ids or a template, never by copying another run.
_user_guard = guard(Permission.CONTENT_READ, Permission.RUNS_TRIGGER, scope=Scope.PROJECT)
HIDDEN = "[HIDDEN]"


def commit_url(web_url: str | None, commit: str | None) -> str | None:
    """A link to the commit on its forge (GitLab's path differs from GitHub's and Gitea's)."""
    if not web_url or not commit:
        return None
    separator = "/-/commit/" if "gitlab" in web_url.lower() else "/commit/"
    return f"{web_url.rstrip('/')}{separator}{commit}"


def _run_out(db: Session, run: Run, user: User) -> RunOut:
    out = RunOut.model_validate(run)
    if run.git_source_id is not None:
        source = db.get(GitSource, run.git_source_id)
        out.commit_url = commit_url(source.web_url if source else None, run.git_commit)
    can_see = Permission.RUNS_READ_EXTRA_VARS in project_permissions(db, user, run.project_id)
    if out.extra_vars and not can_see:
        out.extra_vars = dict.fromkeys(out.extra_vars, HIDDEN)
    return out


@router.get("", response_model=list[RunOut])
def list_runs(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[RunOut]:
    ids = readable_project_ids(db, user, request, Permission.CONTENT_READ, project_id)
    query = db.query(Run)
    if ids is not None:
        query = query.filter(Run.project_id.in_(ids))
    return [_run_out(db, run, user) for run in query.order_by(Run.id.desc()).all()]


def _pin_snapshot(db: Session, playbook: Playbook) -> dict:
    """A synced playbook runs inside its repository at the source's current commit. The
    snapshot row is share-locked until the run is committed, so a sync can't supersede (and
    the reaper can't prune) it in between; afterwards the queued run pins it."""
    if playbook.missing_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This playbook is no longer in its git repository"
        )
    source = db.get(GitSource, playbook.source_id)
    snapshot = (
        db.scalars(
            select(GitSnapshot)
            .where(GitSnapshot.id == source.current_snapshot_id)
            .with_for_update(read=True)
        ).first()
        if source is not None and source.current_snapshot_id is not None
        else None
    )
    if snapshot is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "The git source has not synced yet")
    try:
        text = git_sync.read_member(snapshot, playbook.repo_path)
    except (git_sync.SyncError, OSError) as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "The playbook is missing from the synced commit"
        ) from exc
    return {
        "text": text,
        "columns": {
            "git_source_id": source.id,
            "git_source_name": source.name,
            "git_snapshot_id": snapshot.id,
            "git_commit": snapshot.commit,
            "playbook_path": playbook.repo_path,
        },
    }


def _pin_inventory(
    db: Session, inventory: Inventory, group: InventoryGroup | None, group_name: str | None
) -> tuple[dict, str | None, InventorySnapshot | None]:
    """The inventory's own hosts and groups as they are now and its sources' current snapshot
    (what the queued run will see, whatever is edited or refreshed meanwhile), and the target
    group's name, checked against the merged tree. The snapshot row is share-locked until the
    run is committed, so pruning can't remove it in between."""
    snapshot = None
    if has_sources(db, inventory.id):
        if inventory.current_snapshot_id is not None:
            snapshot = db.scalars(
                select(InventorySnapshot)
                .where(InventorySnapshot.id == inventory.current_snapshot_id)
                .with_for_update(read=True)
            ).first()
        if snapshot is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "This inventory's dynamic sources haven't been refreshed yet",
            )
    static = static_data(inventory)
    if problems := static_problems(static):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Rename these in the inventory before running it: " + "; ".join(problems[:5]),
        )
    if len(json.dumps(static)) > MAX_INVENTORY_PIN_BYTES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"The inventory is too large to run (over {MAX_INVENTORY_PIN_BYTES // 2**20} MiB)",
        )
    target = group.name if group is not None else group_name
    merged = merge(static, snapshot.data if snapshot is not None else None)
    if target is not None and target not in merged["groups"]:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"No group named {target!r} in this inventory"
        )
    return static, target, snapshot


def _require_same_project(obj, project_id: int, label: str) -> None:
    if obj.project_id != project_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"{label} must belong to the same project as the playbook"
        )


def queue_run(
    db: Session,
    current_user: User,
    request: Request,
    payload: RunCreate,
    *,
    audit_detail: dict | None = None,
) -> Run:
    """Checks a run request (the caller's permissions, and that everything is in the
    playbook's project), pins what it will execute and queues it. Shared by POST /runs, the
    re-run and template launches; audit_detail says where the request came from."""

    def denied_become(project_id: int | None) -> HTTPException:
        audit.record(
            db,
            "permission.denied",
            outcome="denied",
            actor=current_user,
            target_type="run",
            ip=client_ip(request),
            project_id=project_id,
            detail={"required": Permission.RUNS_BECOME.value},
        )
        return HTTPException(
            status.HTTP_403_FORBIDDEN, "You may not run playbooks as root (become)"
        )

    # Cheap early rejection: a user who can't use become in *any* project.
    if payload.become and not holds_somewhere(db, current_user, Permission.RUNS_BECOME):
        raise denied_become(None)

    # The playbook fixes the run's project; everything else must live in it.
    playbook = get_scoped(
        db,
        current_user,
        request,
        Playbook,
        payload.playbook_id,
        Permission.RUNS_TRIGGER,
        "Playbook not found",
    )
    project_id = playbook.project_id
    git = _pin_snapshot(db, playbook) if playbook.source_id is not None else None
    if payload.become and Permission.RUNS_BECOME not in project_permissions(
        db, current_user, project_id
    ):
        raise denied_become(project_id)

    inventory = get_scoped(
        db,
        current_user,
        request,
        Inventory,
        payload.inventory_id,
        Permission.CONTENT_READ,
        "Inventory not found",
    )
    _require_same_project(inventory, project_id, "Inventory")

    group = None
    if payload.group_id is not None:
        group = db.get(InventoryGroup, payload.group_id)
        if group is None or group.inventory_id != payload.inventory_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "group_id does not belong to this inventory"
            )
        if payload.group_name is not None and payload.group_name != group.name:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "group_id and group_name name different groups"
            )
    inventory_static, group_name, snapshot = _pin_inventory(
        db, inventory, group, payload.group_name
    )
    if group is None and group_name is not None:
        # A static group picked by name: keep the link, for history.
        group = next((g for g in inventory.groups if g.name == group_name), None)

    credential = get_scoped(
        db,
        current_user,
        request,
        Credential,
        payload.credential_id,
        Permission.SECRETS_LIST,
        "Credential not found",
    )
    _require_same_project(credential, project_id, "Credential")
    if credential.kind != "ssh":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A run needs an SSH key credential")

    vault_password = None
    if payload.vault_password_id is not None:
        vault_password = get_scoped(
            db,
            current_user,
            request,
            VaultPassword,
            payload.vault_password_id,
            Permission.SECRETS_LIST,
            "Vault password not found",
        )
        _require_same_project(vault_password, project_id, "Vault password")

    # The run executes the playbook as it is now, whatever happens to it while queued; a
    # synced one inside its repository at the commit current now (see _pin_snapshot).
    playbook_text = git["text"].encode() if git else playbook_path(playbook.id).read_bytes()
    if len(playbook_text) > MAX_PLAYBOOK_SNAPSHOT_BYTES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"The playbook is too large to run (over {MAX_PLAYBOOK_SNAPSHOT_BYTES // 1024} KiB)",
        )

    run = Run(
        project_id=project_id,
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        inventory_id=inventory.id,
        inventory_name=inventory.name,
        group_id=group.id if group else None,
        group_name=group_name,
        inventory_static=inventory_static,
        inventory_snapshot_id=snapshot.id if snapshot is not None else None,
        credential_id=credential.id,
        credential_name=credential.name,
        vault_password_id=vault_password.id if vault_password else None,
        vault_password_name=vault_password.name if vault_password else None,
        become=payload.become,
        check_mode=payload.check_mode,
        diff_mode=payload.diff_mode,
        limit=payload.limit,
        extra_vars=payload.extra_vars,
        triggered_by=current_user.username,
        triggered_by_api_key_id=getattr(current_user, "_api_key_id", None),
        timeout_seconds=payload.timeout_seconds,
        playbook_snapshot=playbook_text.decode("utf-8"),
        playbook_sha256=hashlib.sha256(playbook_text).hexdigest(),
        **(git["columns"] if git else {}),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    metrics.run_queued(project_id, via_api_key=run.triggered_by_api_key_id is not None)

    audit.record(
        db,
        "run.trigger",
        actor=current_user,
        target_type="run",
        target_id=run.id,
        ip=client_ip(request),
        project_id=project_id,
        detail={
            "playbook": playbook.name,
            "inventory": inventory.name,
            "group": group_name,
            "become": payload.become,
            "check_mode": payload.check_mode,
            **({"commit": run.git_commit} if run.git_commit else {}),
            **(audit_detail or {}),
        },
    )
    notifier.notify(QUEUE_TOPIC)  # wake the workers waiting for a claim
    return run


@router.post("", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def create_run(
    payload: RunCreate,
    request: Request,
    current_user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    return _run_out(db, queue_run(db, current_user, request, payload), current_user)


def deleted_items_conflict(what: str, missing: list[str]) -> HTTPException:
    verb = "has" if len(missing) == 1 else "have"
    return HTTPException(
        status.HTTP_409_CONFLICT,
        f"{what} can't be started: its {', '.join(missing)} {verb} been deleted",
    )


def _deleted_references(run: Run) -> list[str]:
    missing = [
        label
        for label, ref in (
            ("playbook", run.playbook_id),
            ("inventory", run.inventory_id),
            ("credential", run.credential_id),
        )
        if ref is None
    ]
    if run.vault_password_name is not None and run.vault_password_id is None:
        missing.append("vault password")
    return missing


@router.post("/{run_id}/rerun", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def rerun(
    run_id: int,
    request: Request,
    current_user: User = Depends(_user_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    """Starts the run again with the same playbook, inventory and target, credential, vault
    password and options (extra vars included), each as it is now: a synced playbook runs at
    its source's current commit. 409 when one of them has been deleted."""
    run = get_scoped(
        db, current_user, request, Run, run_id, Permission.RUNS_TRIGGER, "Run not found"
    )
    if missing := _deleted_references(run):
        raise deleted_items_conflict(f"Run #{run_id}", missing)
    payload = RunCreate(
        playbook_id=run.playbook_id,
        inventory_id=run.inventory_id,
        group_name=run.group_name,
        credential_id=run.credential_id,
        vault_password_id=run.vault_password_id,
        become=run.become,
        check_mode=run.check_mode,
        diff_mode=run.diff_mode,
        limit=run.limit,
        extra_vars=run.extra_vars,
        timeout_seconds=min(run.timeout_seconds, MAX_RUN_TIMEOUT_SECONDS),
    )
    new_run = queue_run(db, current_user, request, payload, audit_detail={"rerun_of": run.id})
    return _run_out(db, new_run, current_user)


@router.get("/{run_id}", response_model=RunOut)
def get_run(
    run_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    run = get_scoped(db, user, request, Run, run_id, Permission.CONTENT_READ, "Run not found")
    out = _run_out(db, run, user)
    if run.status == RunStatus.QUEUED.value:
        out.waiting_reason = wait_reason(db, run)
    return out


@router.post("/{run_id}/cancel", response_model=RunOut)
def cancel_run(
    run_id: int,
    request: Request,
    current_user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    """A queued run is cancelled at once. A running one is marked, and its worker stops it
    (it learns within a heartbeat); the reaper ends it if the worker never confirms."""
    run = get_scoped(
        db, current_user, request, Run, run_id, Permission.RUNS_TRIGGER, "Run not found"
    )
    key_id = getattr(current_user, "_api_key_id", None)
    if key_id is not None and run.triggered_by_api_key_id != key_id:
        audit.record(
            db,
            "permission.denied",
            outcome="denied",
            actor=current_user,
            target_type="run",
            target_id=run_id,
            ip=client_ip(request),
            project_id=run.project_id,
            detail={"reason": "api keys may only cancel their own runs"},
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "An API key may only cancel runs it triggered"
        )

    # Re-read under the row lock: a worker may have claimed or finished it meanwhile.
    run = db.scalars(
        select(Run)
        .where(Run.id == run_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    if run.status in FINISHED_STATUSES:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Run #{run_id} has already finished ({run.status})"
        )
    if run.cancel_requested_at is not None:  # already asked: nothing more to do
        return _run_out(db, run, current_user)

    was_queued = run.status == RunStatus.QUEUED.value
    run.cancel_requested_at = func.now()
    run.cancel_requested_by = current_user.username
    if was_queued:
        fail_run(
            run, RunStatus.CANCELLED, f"cancelled by {current_user.username} before it started"
        )
    db.commit()
    db.refresh(run)

    audit.record(
        db,
        "run.cancel",
        actor=current_user,
        target_type="run",
        target_id=run_id,
        ip=client_ip(request),
        project_id=run.project_id,
        detail={"was": "queued" if was_queued else "running"},
    )
    if was_queued:
        notifier.notify(run_topic(run_id))  # its viewers see the end of the log
        notifier.notify(QUEUE_TOPIC)  # the next run on its inventory may start now
    return _run_out(db, run, current_user)


# Colour and cursor codes in Ansible's output (CSI and OSC sequences, and two-byte escapes).
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_EXPORT_CHUNK_BYTES = 64 * 1024


def _committed_chunks(path: Path, length: int) -> Iterator[bytes]:
    """The log's first `length` bytes: what has been committed (a write still in flight, or
    one whose commit never happened, is left out)."""
    try:
        log = path.open("rb")
    except FileNotFoundError:  # a queued run has no log yet
        return
    with log:
        remaining = length
        while remaining > 0 and (chunk := log.read(min(remaining, _EXPORT_CHUNK_BYTES))):
            remaining -= len(chunk)
            yield chunk


def _committed_lines(path: Path, length: int) -> Iterator[bytes]:
    try:
        log = path.open("rb")
    except FileNotFoundError:
        return
    with log:
        remaining = length
        while remaining > 0 and (line := log.readline(remaining)):
            remaining -= len(line)
            yield line


def _as_text(lines: Iterator[bytes]) -> Iterator[bytes]:
    for raw in lines:
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        text = event.get("stdout") if isinstance(event, dict) else None
        if isinstance(text, str) and text:
            yield (_ANSI.sub("", text).replace("\r\n", "\n") + "\n").encode()


_EXPORT_FORMATS = {
    "text": ("log", "text/plain; charset=utf-8"),
    "jsonl": ("jsonl", "application/x-ndjson"),
}


@router.get(
    "/{run_id}/log",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "The run's output as a file",
            "content": {"text/plain": {}, "application/x-ndjson": {}},
        }
    },
)
def export_log(
    run_id: int,
    request: Request,
    fmt: Literal["text", "jsonl"] = Query("text", alias="format"),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """The run's output as a download: `text` is each event's output with colour codes
    removed, `jsonl` Ansible's events as stored (one JSON object per line, as the WebSocket
    sends them). For a run still going, what it has produced so far. Secret values known to
    AnsiDeck were removed before the output was stored."""
    run = get_scoped(db, user, request, Run, run_id, Permission.CONTENT_READ, "Run not found")
    path, length = run_log_path(run.id), run.log_bytes
    extension, media_type = _EXPORT_FORMATS[fmt]
    body = (
        _committed_chunks(path, length)
        if fmt == "jsonl"
        else _as_text(_committed_lines(path, length))
    )
    return StreamingResponse(
        body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="ansideck-run-{run.id}.{extension}"'
        },
    )


# How long a live log viewer waits for a notification before re-checking the run itself.
_STATUS_RECHECK_SECONDS = 2.0
# Upper bound on what one read of the log pulls into memory (a single line may exceed it).
_TAIL_READ_BYTES = 1 << 20


class _LogTail:
    """Reads a run's JSONL log incrementally, complete lines only, from a byte offset. The
    file is the single source of truth for live and finished runs alike; skip_lines lets a
    reconnecting viewer resume after the lines it already has."""

    def __init__(self, path: Path, skip_lines: int) -> None:
        self.path = path
        self.offset = 0
        self.skip_lines = skip_lines

    def read(self) -> list[str]:
        lines: list[str] = []
        size = 0
        try:
            with self.path.open("rb") as log:
                log.seek(self.offset)
                for raw in log:
                    if not raw.endswith(b"\n"):
                        break  # still being written; picked up by the next read
                    self.offset += len(raw)
                    line = raw.decode("utf-8").strip()
                    if not line:
                        continue
                    if self.skip_lines:
                        self.skip_lines -= 1
                        continue
                    lines.append(line)
                    size += len(raw)
                    if size >= _TAIL_READ_BYTES:
                        break
        except FileNotFoundError:  # a queued run has no log yet
            pass
        return lines


def _run_finished(run_id: int) -> bool:
    """Its own short-lived session: a stream can last as long as the run, and must not sit
    "idle in transaction" holding locks (they block TRUNCATE and migrations)."""
    db = get_sessionmaker()()
    try:
        row = db.execute(select(Run.finished_at).where(Run.id == run_id)).first()
    finally:
        db.close()
    return row is None or row.finished_at is not None


async def _stream_log(websocket: WebSocket, run_id: int, skip_lines: int, finished: bool) -> None:
    tail = _LogTail(run_log_path(run_id), skip_lines)
    # Listen before the first read, so a line written in between still wakes this loop.
    with notifier.listen(run_topic(run_id)) as listener:
        while True:
            lines = tail.read()
            for line in lines:
                await websocket.send_text(line)
            if lines:
                continue
            # A run is only marked finished once every line is in the log (the API refuses a
            # worker's result until then), so one more drain yields the complete output.
            if finished or await asyncio.to_thread(_run_finished, run_id):
                while lines := tail.read():
                    for line in lines:
                        await websocket.send_text(line)
                return
            await listener.wait(_STATUS_RECHECK_SECONDS)


async def _until_disconnect(websocket: WebSocket) -> None:
    while (await websocket.receive())["type"] != "websocket.disconnect":
        pass


@router.websocket("/{run_id}/ws")
async def run_ws(
    websocket: WebSocket,
    run_id: int,
    from_line: int = Query(0, alias="from", ge=0),
    db: Session = Depends(get_db),
) -> None:
    """Streams the run's log, one JSON event per message, then closes with code 1000 once
    the run has finished and every line was sent. Any other close means the output was
    cut short: reconnect with ?from=<lines received so far> to resume."""
    # Manually guarded (no Depends on a WebSocket): authenticate the cookie (or an
    # Authorization header, for CI clients) against the DB and require the same read
    # permission as the HTTP routes.
    try:
        user = authenticate_request(
            db,
            cookie_token=websocket.cookies.get(SESSION_COOKIE_NAME),
            authorization=websocket.headers.get("authorization"),
            ip=client_ip(websocket),
        )
    except RateLimited:
        user = None
    if user is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Missing run and "not your project" close identically (no existence oracle).
    run = db.get(Run, run_id)
    if run is None or Permission.CONTENT_READ not in project_permissions(db, user, run.project_id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    finished = run.finished_at is not None
    db.close()  # see _run_finished

    await websocket.accept()

    streaming = asyncio.create_task(_stream_log(websocket, run_id, from_line, finished))
    disconnected = asyncio.create_task(_until_disconnect(websocket))
    client_gone = True
    try:
        # A viewer that goes away mid-run is noticed at once, not at the next line.
        done, _ = await asyncio.wait({streaming, disconnected}, return_when=asyncio.FIRST_COMPLETED)
        if streaming in done:
            streaming.result()  # re-raises a streaming failure
            client_gone = False
    except WebSocketDisconnect:
        pass
    finally:
        for task in (streaming, disconnected):
            task.cancel()
        await asyncio.gather(streaming, disconnected, return_exceptions=True)
    if not client_gone:
        # The viewer may leave just as the stream ends (e.g. a replay racing a page reload).
        with contextlib.suppress(WebSocketDisconnect, RuntimeError):
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
