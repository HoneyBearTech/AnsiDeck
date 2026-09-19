from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.crypto import encrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import User, VaultPassword
from app.permissions import Permission, guard
from app.schemas.vault_passwords import VaultPasswordCreate, VaultPasswordOut

_guard = guard(Permission.SECRETS_LIST, Permission.SECRETS_MANAGE)
router = APIRouter(dependencies=[Depends(_guard)])


@router.get("", response_model=list[VaultPasswordOut])
def list_vault_passwords(db: Session = Depends(get_db)) -> list[VaultPassword]:
    return db.query(VaultPassword).order_by(VaultPassword.name).all()


@router.post("", response_model=VaultPasswordOut, status_code=status.HTTP_201_CREATED)
def create_vault_password(
    payload: VaultPasswordCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> VaultPassword:
    vault_password = VaultPassword(
        name=payload.name,
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
    )
    return vault_password


@router.delete("/{vault_password_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vault_password(
    vault_password_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    vault_password = db.get(VaultPassword, vault_password_id)
    if vault_password is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault password not found")
    name = vault_password.name
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
    )
