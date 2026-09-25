import asyncio
import contextlib
from pathlib import Path

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
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db, get_sessionmaker
from app.dependencies import SESSION_COOKIE_NAME, RateLimited, authenticate_request
from app.hardening import client_ip
from app.models import (
    Credential,
    GalaxyInstall,
    Inventory,
    InventoryGroup,
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
from app.run_engine import start_run
from app.schemas.runs import RunCreate, RunOut
from app.scoping import get_scoped, readable_project_ids
from app.storage import run_log_path

router = APIRouter()

_ACTIVE_STATUSES = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)


# The only routes an API key may reach (a test pins this set).
_guard = guard(Permission.CONTENT_READ, Permission.RUNS_TRIGGER, scope=Scope.PROJECT, api_key=True)
HIDDEN = "[HIDDEN]"


def _run_out(db: Session, run: Run, user: User) -> RunOut:
    out = RunOut.model_validate(run)
    can_see = Permission.RUNS_READ_EXTRA_VARS in project_permissions(db, user, run.project_id)
    if out.extra_vars and not can_see:
        out.extra_vars = {key: HIDDEN for key in out.extra_vars}
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


def _require_same_project(obj, project_id: int, label: str) -> None:
    if obj.project_id != project_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"{label} must belong to the same project as the playbook"
        )


@router.post("", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def create_run(
    payload: RunCreate,
    request: Request,
    current_user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunOut:
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

    # Coarse guard: block a second run against the same inventory while one
    # is already active, rather than resolving exact host-set overlap. Zero
    # false negatives (any real host collision is necessarily within the
    # same inventory); the one false-positive case (two disjoint groups in
    # the same inventory) is an acceptable trade for a single-user tool —
    # a real job queue is Phase 4's job, not this guard's.
    conflicting = (
        db.query(Run)
        .filter(Run.inventory_id == payload.inventory_id, Run.status.in_(_ACTIVE_STATUSES))
        .first()
    )
    if conflicting is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Inventory '{inventory.name}' already has an active run "
            f"(#{conflicting.id}, status={conflicting.status})",
        )

    active_install = (
        db.query(GalaxyInstall).filter(GalaxyInstall.status.in_(_ACTIVE_STATUSES)).first()
    )
    if active_install is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A role/collection install (#{active_install.id}) is in progress; "
            "wait for it to finish before starting a run",
        )

    run = Run(
        project_id=project_id,
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        inventory_id=inventory.id,
        inventory_name=inventory.name,
        group_id=group.id if group else None,
        group_name=group.name if group else None,
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
    )
    db.add(run)
    db.commit()
    db.refresh(run)

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
            "group": group.name if group else None,
            "become": payload.become,
            "check_mode": payload.check_mode,
        },
    )
    start_run(run.id)
    return _run_out(db, run, current_user)


@router.get("/{run_id}", response_model=RunOut)
def get_run(
    run_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    run = get_scoped(db, user, request, Run, run_id, Permission.CONTENT_READ, "Run not found")
    return _run_out(db, run, user)


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
            # The engine writes the whole log before it marks the run finished, so once the
            # run is finished, draining the file once more yields the complete output.
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
