from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.galaxy import (
    RequirementsError,
    list_installed_collections,
    list_installed_roles,
    try_start_install,
    validate_requirements,
)
from app.hardening import client_ip
from app.models import GalaxyInstall, RunStatus, User
from app.permissions import Permission, Scope, guard
from app.schemas.galaxy import (
    InstallCreate,
    InstallDetail,
    InstalledOut,
    InstallOut,
    RequirementsPayload,
)
from app.storage import galaxy_install_log_path, galaxy_requirements_path

_guard = guard(Permission.CONTENT_READ, Permission.GALAXY_MANAGE, scope=Scope.GLOBAL)
router = APIRouter(dependencies=[Depends(_guard)])

_ACTIVE_STATUSES = (RunStatus.QUEUED.value, RunStatus.RUNNING.value)


def _to_detail(install: GalaxyInstall) -> InstallDetail:
    log_path = galaxy_install_log_path(install.id)
    return InstallDetail(
        **InstallOut.model_validate(install).model_dump(),
        requirements_snapshot=install.requirements_snapshot,
        log=log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else "",
    )


@router.get("/requirements", response_model=RequirementsPayload)
def get_requirements() -> RequirementsPayload:
    path = galaxy_requirements_path()
    return RequirementsPayload(content=path.read_text() if path.exists() else "")


@router.put("/requirements", response_model=RequirementsPayload)
def put_requirements(
    payload: RequirementsPayload,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RequirementsPayload:
    try:
        validate_requirements(payload.content)
    except RequirementsError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    galaxy_requirements_path().write_text(payload.content)
    audit.record(
        db,
        "galaxy.requirements_update",
        actor=actor,
        target_type="galaxy_requirements",
        ip=client_ip(request),
    )
    return payload


@router.get("/installed", response_model=InstalledOut)
def get_installed() -> InstalledOut:
    return InstalledOut(collections=list_installed_collections(), roles=list_installed_roles())


@router.get("/installs", response_model=list[InstallOut])
def list_installs(db: Session = Depends(get_db)) -> list[GalaxyInstall]:
    return db.query(GalaxyInstall).order_by(GalaxyInstall.id.desc()).all()


@router.get("/installs/{install_id}", response_model=InstallDetail)
def get_install(install_id: int, db: Session = Depends(get_db)) -> InstallDetail:
    install = db.get(GalaxyInstall, install_id)
    if install is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Install not found")
    return _to_detail(install)


@router.post("/installs", response_model=InstallDetail, status_code=status.HTTP_201_CREATED)
def create_install(
    payload: InstallCreate,
    request: Request,
    current_user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> InstallDetail:
    path = galaxy_requirements_path()
    text = path.read_text() if path.exists() else ""
    try:
        requirements = validate_requirements(text)
    except RequirementsError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if not requirements["collections"] and not requirements["roles"]:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Nothing to install: requirements are empty"
        )

    active_install = (
        db.query(GalaxyInstall).filter(GalaxyInstall.status.in_(_ACTIVE_STATUSES)).first()
    )
    if active_install is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Install #{active_install.id} is already queued or running"
        )
    install = GalaxyInstall(
        requirements_snapshot=text, upgrade=payload.upgrade, triggered_by=current_user.username
    )
    db.add(install)
    db.commit()
    db.refresh(install)

    audit.record(
        db,
        "galaxy.install",
        actor=current_user,
        target_type="galaxy_install",
        target_id=install.id,
        ip=client_ip(request),
        detail={"upgrade": payload.upgrade},
    )
    # Starts now if no run is running; otherwise once they finish (no new run starts meanwhile).
    try_start_install()
    db.refresh(install)
    return _to_detail(install)
