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
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.dependencies import SESSION_COOKIE_NAME, authenticate_token
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
from app.permissions import (
    Permission,
    Scope,
    guard,
    holds_somewhere,
    project_permissions,
)
from app.run_engine import DONE, get_or_create_stream, start_run
from app.schemas.runs import RunCreate, RunOut
from app.scoping import get_scoped, readable_project_ids
from app.storage import run_log_path

router = APIRouter()

_ACTIVE_STATUSES = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)


_guard = guard(Permission.CONTENT_READ, Permission.RUNS_TRIGGER, scope=Scope.PROJECT)
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


@router.websocket("/{run_id}/ws")
async def run_ws(websocket: WebSocket, run_id: int, db: Session = Depends(get_db)) -> None:
    # Manually guarded (no Depends on a WebSocket): authenticate the cookie
    # against the DB and require the same read permission as the HTTP routes.
    user = authenticate_token(db, websocket.cookies.get(SESSION_COOKIE_NAME))
    if user is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Missing run and "not your project" close identically (no existence oracle).
    run = db.get(Run, run_id)
    if run is None or Permission.CONTENT_READ not in project_permissions(db, user, run.project_id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()

    try:
        if run.finished_at is not None:
            log_path = run_log_path(run_id)
            if log_path.exists():
                for line in log_path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        await websocket.send_text(line)
            return

        stream = get_or_create_stream(run_id)
        backlog, queue = stream.subscribe()
        for event in backlog:
            await websocket.send_json(event)

        while True:
            item = await queue.get()
            if item is DONE:
                break
            await websocket.send_json(item)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
