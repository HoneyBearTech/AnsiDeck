from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.crypto import encrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import User, VaultPassword
from app.permissions import Permission, Scope, guard
from app.schemas.vault_passwords import VaultPasswordCreate, VaultPasswordOut
from app.scoping import get_scoped, readable_project_ids, resolve_write_project

_guard = guard(Permission.SECRETS_LIST, Permission.SECRETS_MANAGE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


@router.get("", response_model=list[VaultPasswordOut])
def list_vault_passwords(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[VaultPassword]:
    ids = readable_project_ids(db, user, request, Permission.SECRETS_LIST, project_id)
    query = db.query(VaultPassword)
    if ids is not None:
        query = query.filter(VaultPassword.project_id.in_(ids))
    return query.order_by(VaultPassword.name).all()


@router.post("", response_model=VaultPasswordOut, status_code=status.HTTP_201_CREATED)
def create_vault_password(
    payload: VaultPasswordCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> VaultPassword:
    project_id = resolve_write_project(
        db, actor, request, payload.project_id, Permission.SECRETS_MANAGE
    )
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
    )
    return vault_password


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
