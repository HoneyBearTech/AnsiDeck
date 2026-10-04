from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, secret_store
from app.crypto import encrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import User, VaultPassword
from app.permissions import Permission, Scope, guard
from app.routers.credentials import check_reference, read_reference, throttled_check
from app.schemas.credentials import SecretCheck
from app.schemas.vault_passwords import VaultPasswordCreate, VaultPasswordOut
from app.scoping import get_scoped, readable_project_ids, resolve_write_project

_guard = guard(Permission.SECRETS_LIST, Permission.SECRETS_MANAGE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


def _out(vault_password: VaultPassword) -> dict:
    return {
        "id": vault_password.id,
        "name": vault_password.name,
        "description": vault_password.description,
        "project_id": vault_password.project_id,
        "created_at": vault_password.created_at,
        **secret_store.reference_fields(vault_password),
    }


def _non_empty(value: str) -> None:
    if not value.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The stored password is empty")


@router.get("", response_model=list[VaultPasswordOut])
def list_vault_passwords(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    ids = readable_project_ids(db, user, request, Permission.SECRETS_LIST, project_id)
    query = db.query(VaultPassword)
    if ids is not None:
        query = query.filter(VaultPassword.project_id.in_(ids))
    return [_out(vp) for vp in query.order_by(VaultPassword.name).all()]


@router.post("", response_model=VaultPasswordOut, status_code=status.HTTP_201_CREATED)
def create_vault_password(
    payload: VaultPasswordCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    project_id = resolve_write_project(
        db, actor, request, payload.project_id, Permission.SECRETS_MANAGE
    )
    detail: dict | None = None
    if payload.store_path is not None:
        value, version = read_reference(project_id, payload.store_path, payload.store_key)
        _non_empty(value)
        del value
        vault_password = VaultPassword(
            name=payload.name,
            project_id=project_id,
            description=payload.description,
            store_path=payload.store_path,
            store_key=payload.store_key,
        )
        detail = {
            "store": "external",
            "location": secret_store.location(project_id, payload.store_path, payload.store_key),
            "version": version,
        }
    else:
        vault_password = VaultPassword(
            name=payload.name,
            project_id=project_id,
            description=payload.description,
            encrypted_password=encrypt_secret(payload.password.encode()),
        )
    db.add(vault_password)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Vault password name already exists"
        ) from exc
    db.refresh(vault_password)
    audit.record(
        db,
        "vault_password.create",
        actor=actor,
        target_type="vault_password",
        target_id=vault_password.id,
        target_name=vault_password.name,
        ip=client_ip(request),
        project_id=vault_password.project_id,
        detail=detail,
    )
    return _out(vault_password)


@router.post("/{vault_password_id}/check", response_model=SecretCheck)
def check_vault_password(
    vault_password_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Whether the password can be read now (from the secret store); never returns it."""
    vault_password = get_scoped(
        db, actor, request, VaultPassword, vault_password_id, Permission.SECRETS_MANAGE,
        "Vault password not found",
    )  # fmt: skip
    throttled_check(actor)
    return check_reference(
        db, actor, request, vault_password, "vault_password", validate=_non_empty
    )


@router.delete("/{vault_password_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vault_password(
    vault_password_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    vault_password = get_scoped(
        db,
        actor,
        request,
        VaultPassword,
        vault_password_id,
        Permission.SECRETS_MANAGE,
        "Vault password not found",
    )
    name, project_id = vault_password.name, vault_password.project_id
    db.delete(vault_password)
    db.commit()
    audit.record(
        db,
        "vault_password.delete",
        actor=actor,
        target_type="vault_password",
        target_id=vault_password_id,
        target_name=name,
        ip=client_ip(request),
        project_id=project_id,
    )
