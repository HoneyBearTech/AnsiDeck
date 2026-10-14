from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.api_keys import (
    creator_problem,
    hash_token,
    key_status,
    lifetime_days,
    new_token,
    parse_networks,
)
from app.db import get_db
from app.hardening import client_ip
from app.models import ApiKey, Inventory, Playbook, User
from app.permissions import Permission, Scope, guard
from app.routers.auth import check_reauthentication
from app.schemas.api_keys import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyLimits,
    ApiKeyOut,
    ApiKeyRotate,
)
from app.scoping import require_project_permission

router = APIRouter()

# Cookie sessions only: the guard refuses API keys, so a key can't mint or revoke keys.
_guard = guard(Permission.API_KEYS_MANAGE, Permission.API_KEYS_MANAGE, scope=Scope.PROJECT)

MAX_KEYS_PER_PROJECT = 50


def _out(db: Session, key: ApiKey, **extra) -> dict:
    status_, problem = key_status(key), None
    if status_ == "active" and (problem := creator_problem(db, key)):
        status_ = "suspended"
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
        "status": status_,
        "suspended_because": problem,
        "allowed_networks": key.allowed_networks,
        "allowed_playbooks": _named(db, Playbook, key.allowed_playbook_ids),
        "allowed_inventories": _named(db, Inventory, key.allowed_inventory_ids),
        **extra,
    }


def _named(db: Session, model, ids: list[int] | None) -> list[dict] | None:
    if ids is None:
        return None
    return [{"id": obj.id, "name": obj.name} for i in ids if (obj := db.get(model, i))]


def _limits(db: Session, project_id: int, payload: ApiKeyLimits) -> dict:
    """The limits as stored: networks normalised, the playbooks and inventories checked to be
    the project's. An empty list removes the limit, like null."""
    limits: dict = {}
    if payload.allowed_networks is not None:
        try:
            limits["allowed_networks"] = parse_networks(payload.allowed_networks) or None
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    for field, model, label in (
        ("allowed_playbook_ids", Playbook, "playbook"),
        ("allowed_inventory_ids", Inventory, "inventory"),
    ):
        ids = getattr(payload, field)
        if ids is None:
            continue
        ids = list(dict.fromkeys(ids))
        for item_id in ids:
            obj = db.get(model, item_id)
            if obj is None or obj.project_id != project_id:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, f"No {label} {item_id} in this project"
                )
        limits[field] = ids or None
    return limits


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    project_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    keys = db.query(ApiKey).filter(ApiKey.project_id == project_id).order_by(ApiKey.id.desc()).all()
    return [_out(db, key) for key in keys]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    project_id: int,
    payload: ApiKeyCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    # A key outlives the session that made it: a stolen session must not be enough.
    check_reauthentication(db, request, user, payload.current_password, "apikey.create")
    now = datetime.now(UTC)

    existing = db.query(ApiKey).filter(ApiKey.project_id == project_id).all()
    if any(key.name == payload.name and key.revoked_at is None for key in existing):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This project already has an API key with that name"
        )
    if sum(1 for key in existing if key_status(key, now) == "active") >= MAX_KEYS_PER_PROJECT:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A project can have at most {MAX_KEYS_PER_PROJECT} active API keys. Revoke one first.",
        )

    limits = _limits(db, project_id, payload)
    key, token = _new_key(
        db, project_id, payload.name, payload.preset, user, payload.expires_in_days
    )
    for field, value in limits.items():
        setattr(key, field, value)
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
            **{k: v for k, v in limits.items() if v is not None},
        },
    )
    return _out(db, key, token=token)


def _new_key(
    db: Session, project_id: int, name: str, preset: str, user: User, days: int
) -> tuple[ApiKey, str]:
    token, prefix = new_token()
    while db.query(ApiKey).filter(ApiKey.prefix == prefix).first() is not None:
        token, prefix = new_token()  # 32-bit prefix collision: vanishingly rare
    key = ApiKey(
        project_id=project_id,
        name=name,
        preset=preset,
        prefix=prefix,
        token_hash=hash_token(token),
        created_by=user.username,
        created_by_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=days),
    )
    db.add(key)
    db.flush()
    return key, token


@router.post("/{key_id}/rotate", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def rotate_api_key(
    project_id: int,
    key_id: int,
    payload: ApiKeyRotate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Replaces the key with a new one of the same name, preset and lifetime, created by the
    caller; the old one stops working at once."""
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    check_reauthentication(db, request, user, payload.current_password, "apikey.rotate")
    old = db.get(ApiKey, key_id, with_for_update=True)
    if old is None or old.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if old.revoked_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This key is revoked. Create a new one instead."
        )
    old.revoked_at = datetime.now(UTC)
    old.revoked_by = user.username
    db.flush()  # frees the name for the replacement
    key, token = _new_key(db, project_id, old.name, old.preset, user, lifetime_days(old))
    key.allowed_networks = old.allowed_networks
    key.allowed_playbook_ids = old.allowed_playbook_ids
    key.allowed_inventory_ids = old.allowed_inventory_ids
    db.commit()
    db.refresh(key)
    audit.record(
        db,
        "apikey.rotate",
        actor=user,
        target_type="api_key",
        target_id=key.id,
        target_name=key.name,
        ip=client_ip(request),
        project_id=project_id,
        detail={
            "preset": key.preset,
            "prefix": key.prefix,
            "replaces": old.prefix,
            "expires_at": key.expires_at.isoformat(),
        },
    )
    return _out(db, key, token=token)


_LIMIT_FIELDS = ("allowed_networks", "allowed_playbook_ids", "allowed_inventory_ids")


@router.patch("/{key_id}", response_model=ApiKeyOut)
def update_api_key_limits(
    project_id: int,
    key_id: int,
    payload: ApiKeyLimits,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Changes a key's limits (the fields sent; null or [] removes a limit). The token stays."""
    require_project_permission(db, user, request, project_id, Permission.API_KEYS_MANAGE)
    key = db.get(ApiKey, key_id, with_for_update=True)
    if key is None or key.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This key is revoked")
    sent = payload.model_fields_set & set(_LIMIT_FIELDS)
    limits = _limits(db, project_id, payload)
    before = {field: getattr(key, field) for field in sent}
    for field in sent:
        setattr(key, field, limits.get(field))
    after = {field: getattr(key, field) for field in sent}
    db.commit()
    if before != after:
        audit.record(
            db,
            "apikey.update",
            actor=user,
            target_type="api_key",
            target_id=key.id,
            target_name=key.name,
            ip=client_ip(request),
            project_id=project_id,
            # Flat: the audit log keeps scalars and lists only.
            detail={
                "prefix": key.prefix,
                **after,
                **{f"{field}_before": value for field, value in before.items()},
            },
        )
    return _out(db, key)


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
