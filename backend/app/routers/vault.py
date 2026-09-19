from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.crypto import decrypt_secret
from app.db import get_db
from app.dependencies import get_current_user
from app.models import VaultPassword
from app.schemas.vault import (
    VaultDecryptRequest,
    VaultDecryptResponse,
    VaultEncryptRequest,
    VaultEncryptResponse,
)
from app.vault import VaultError, decrypt_vault_text, encrypt_to_vault_envelope, to_yaml_block

router = APIRouter(dependencies=[Depends(get_current_user)])


def _load_password(db: Session, vault_password_id: int) -> str:
    vault_password = db.get(VaultPassword, vault_password_id)
    if vault_password is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault password not found")
    return decrypt_secret(vault_password.encrypted_password).decode()


@router.post("/encrypt", response_model=VaultEncryptResponse)
def encrypt(payload: VaultEncryptRequest, db: Session = Depends(get_db)) -> VaultEncryptResponse:
    password = _load_password(db, payload.vault_password_id)
    try:
        envelope = encrypt_to_vault_envelope(payload.plaintext, password)
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Encryption failed: {exc}") from exc
    return VaultEncryptResponse(
        vault_text=envelope, yaml_block=to_yaml_block(envelope, payload.var_name)
    )


@router.post("/decrypt", response_model=VaultDecryptResponse)
def decrypt(payload: VaultDecryptRequest, db: Session = Depends(get_db)) -> VaultDecryptResponse:
    password = _load_password(db, payload.vault_password_id)
    try:
        plaintext = decrypt_vault_text(payload.ciphertext, password)
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Decryption failed: {exc}") from exc
    return VaultDecryptResponse(plaintext=plaintext)
