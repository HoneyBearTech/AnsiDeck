from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.api_keys import hash_token, key_status, new_token
from app.db import get_db
from app.hardening import client_ip
from app.models import ApiKey, User
from app.permissions import Permission, Scope, guard
from app.schemas.api_keys import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.scoping import require_project_permission

router = APIRouter()

# Cookie sessions only: the guard refuses API keys, so a key can't mint or revoke keys.
_guard = guard(Permission.API_KEYS_MANAGE, Permission.API_KEYS_MANAGE, scope=Scope.PROJECT)

MAX_KEYS_PER_PROJECT = 50


def _out(key: ApiKey, **extra) -> dict:
    return {
        "id": key.id,
        "name": key.name,
        "preset": key.preset,
        "prefix": key.prefix,
        "created_by": key.created_by,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
        "last_used_at": key.last_used_at,
        "last_used_ip": key.last_used_ip,
        "revoked_at": key.revoked_at,
        "status": key_status(key),
        **extra,
    }


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    project_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    keys = db.query(ApiKey).filter(ApiKey.project_id == project_id).order_by(ApiKey.id.desc()).all()
    return [_out(key) for key in keys]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    project_id: int,
    payload: ApiKeyCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    now = datetime.now(UTC)

    existing = db.query(ApiKey).filter(ApiKey.project_id == project_id).all()
    if any(key.name == payload.name for key in existing):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This project already has an API key with that name"
        )
    if sum(1 for key in existing if key_status(key, now) == "active") >= MAX_KEYS_PER_PROJECT:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A project can have at most {MAX_KEYS_PER_PROJECT} active API keys. Revoke one first.",
        )

    token, prefix = new_token()
    while db.query(ApiKey).filter(ApiKey.prefix == prefix).first() is not None:
        token, prefix = new_token()  # 32-bit prefix collision: vanishingly rare
    key = ApiKey(
        project_id=project_id,
        name=payload.name,
        preset=payload.preset,
        prefix=prefix,
        token_hash=hash_token(token),
        created_by=user.username,
        expires_at=now + timedelta(days=payload.expires_in_days),
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    audit.record(
        db,
        "apikey.create",
        actor=user,
        target_type="api_key",
        target_id=key.id,
        target_name=key.name,
        ip=client_ip(request),
        project_id=project_id,
        detail={
            "preset": key.preset,
            "prefix": key.prefix,
            "expires_at": key.expires_at.isoformat(),
        },
    )
    return _out(key, token=token)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    project_id: int,
    key_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    key = db.get(ApiKey, key_id)
    if key is None or key.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is not None:
        return  # already revoked; keep the original who/when
    key.revoked_at = datetime.now(UTC)
    key.revoked_by = user.username
    db.commit()
    audit.record(
        db,
        "apikey.revoke",
        actor=user,
        target_type="api_key",
        target_id=key.id,
        target_name=key.name,
        ip=client_ip(request),
        project_id=project_id,
        detail={"preset": key.preset, "prefix": key.prefix},
    )
