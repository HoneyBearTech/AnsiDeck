from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.galaxy import (
    RequirementsError,
    list_installed_collections,
    list_installed_roles,
    start_install,
    validate_requirements,
)
from app.models import GalaxyInstall, Run, RunStatus
from app.schemas.galaxy import (
    InstallCreate,
    InstallDetail,
    InstalledOut,
    InstallOut,
    RequirementsPayload,
)
from app.storage import galaxy_install_log_path, galaxy_requirements_path

router = APIRouter(dependencies=[Depends(get_current_user)])

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
def put_requirements(payload: RequirementsPayload) -> RequirementsPayload:
    try:
        validate_requirements(payload.content)
    except RequirementsError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    galaxy_requirements_path().write_text(payload.content)
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
    current_user: str = Depends(get_current_user),
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
            status.HTTP_409_CONFLICT, f"Install #{active_install.id} is already in progress"
        )
    active_run = db.query(Run).filter(Run.status.in_(_ACTIVE_STATUSES)).first()
    if active_run is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Run #{active_run.id} is active; wait for it to finish before installing "
            "(installs change the roles/collections runs load)",
        )

    install = GalaxyInstall(
        requirements_snapshot=text, upgrade=payload.upgrade, triggered_by=current_user
    )
    db.add(install)
    db.commit()
    db.refresh(install)

    start_install(install.id)
    return _to_detail(install)
