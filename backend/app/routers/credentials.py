from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto import encrypt_secret
from app.db import get_db
from app.dependencies import get_current_user
from app.models import Credential
from app.schemas.credentials import CredentialCreate, CredentialOut

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_db)) -> list[Credential]:
    return db.query(Credential).order_by(Credential.name).all()


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(payload: CredentialCreate, db: Session = Depends(get_db)) -> Credential:
    key_bytes = payload.private_key.encode()
    try:
        load_pem_private_key(key_bytes, password=None)
    except TypeError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "This private key is passphrase-protected. AnsiDeck does not support "
            "passphrase-protected keys yet — please provide an unencrypted key.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid private key: {exc}") from exc

    credential = Credential(
        name=payload.name,
        description=payload.description,
        encrypted_private_key=encrypt_secret(key_bytes),
    )
    db.add(credential)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Credential name already exists") from exc
    db.refresh(credential)
    return credential


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(credential_id: int, db: Session = Depends(get_db)) -> None:
    credential = db.get(Credential, credential_id)
    if credential is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential not found")
    db.delete(credential)
    db.commit()
