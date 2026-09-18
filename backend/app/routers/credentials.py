from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto import encrypt_secret
from app.db import get_db
from app.dependencies import get_current_user
from app.models import Credential
from app.schemas.credentials import CredentialCreate, CredentialOut

router = APIRouter(dependencies=[Depends(get_current_user)])


def _validate_private_key(key_bytes: bytes) -> None:
    # Try both formats: PEM/PKCS8 (e.g. `openssl genpkey`) and the native
    # OpenSSH format (ssh-keygen's default output since OpenSSH 7.8 — the
    # most common real-world key format, especially for ed25519).
    last_error: ValueError | None = None
    for loader in (load_pem_private_key, load_ssh_private_key):
        try:
            loader(key_bytes, password=None)
            return
        except TypeError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "This private key is passphrase-protected. AnsiDeck does not support "
                "passphrase-protected keys yet — please provide an unencrypted key.",
            ) from exc
        except ValueError as exc:
            last_error = exc
    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid private key: {last_error}")


@router.get("", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_db)) -> list[Credential]:
    return db.query(Credential).order_by(Credential.name).all()


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(payload: CredentialCreate, db: Session = Depends(get_db)) -> Credential:
    key_bytes = payload.private_key.encode()
    _validate_private_key(key_bytes)

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
