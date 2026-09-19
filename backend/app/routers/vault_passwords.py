from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto import encrypt_secret
from app.db import get_db
from app.dependencies import get_current_user
from app.models import VaultPassword
from app.schemas.vault_passwords import VaultPasswordCreate, VaultPasswordOut

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[VaultPasswordOut])
def list_vault_passwords(db: Session = Depends(get_db)) -> list[VaultPassword]:
    return db.query(VaultPassword).order_by(VaultPassword.name).all()


@router.post("", response_model=VaultPasswordOut, status_code=status.HTTP_201_CREATED)
def create_vault_password(
    payload: VaultPasswordCreate, db: Session = Depends(get_db)
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
    return vault_password


@router.delete("/{vault_password_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vault_password(vault_password_id: int, db: Session = Depends(get_db)) -> None:
    vault_password = db.get(VaultPassword, vault_password_id)
    if vault_password is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault password not found")
    db.delete(vault_password)
    db.commit()
