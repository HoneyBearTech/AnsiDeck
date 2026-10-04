"""What the UI needs about the secret store: whether it is on and where a project's
references live (to anyone who may list that project's secrets), and the probe's status
(admins, next to the workers)."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app import secret_store
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.permissions import Permission, Scope, guard
from app.schemas.secret_store import SecretStoreInfo, SecretStoreStatus
from app.scoping import require_project_permission

router = APIRouter()

_info_guard = guard(Permission.SECRETS_LIST, None, scope=Scope.PROJECT)
_status_guard = guard(Permission.WORKERS_READ, None, scope=Scope.GLOBAL)


@router.get("/info", response_model=SecretStoreInfo)
def info(
    request: Request,
    project_id: int = Query(...),
    user: User = Depends(_info_guard),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.SECRETS_LIST)
    enabled = secret_store.enabled()
    return {
        "enabled": enabled,
        "label": get_settings().secrets_store_label,
        "base_path": secret_store.base_path(project_id) if enabled else None,
        "path_rules": secret_store.PATH_RULES,
    }


@router.get("/status", response_model=SecretStoreStatus)
def status(_user: User = Depends(_status_guard)) -> dict:
    return {"label": get_settings().secrets_store_label, **secret_store.status()}
