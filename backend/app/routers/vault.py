from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.crypto import decrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import User, VaultPassword
from app.permissions import Permission, Scope, require_permission
from app.schemas.vault import (
    VaultDecryptRequest,
    VaultDecryptResponse,
    VaultEncryptRequest,
    VaultEncryptResponse,
)
from app.scoping import get_scoped
from app.vault import VaultError, decrypt_vault_text, encrypt_to_vault_envelope, to_yaml_block

router = APIRouter()

_encrypt_guard = require_permission(Permission.VAULT_ENCRYPT, scope=Scope.PROJECT)
_decrypt_guard = require_permission(Permission.VAULT_DECRYPT, scope=Scope.PROJECT)


def _load_password(
    db: Session, user: User, request: Request, vault_password_id: int, permission: Permission
) -> tuple[VaultPassword, str]:
    # Scoped by the vault password's own project: encrypt/decrypt follow the secret.
    vault_password = get_scoped(
        db, user, request, VaultPassword, vault_password_id, permission, "Vault password not found"
    )
    return vault_password, decrypt_secret(vault_password.encrypted_password).decode()


def _audit_use(db: Session, action: str, actor: User, request: Request, vp: VaultPassword) -> None:
    audit.record(
        db,
        action,
        actor=actor,
        target_type="vault_password",
        target_id=vp.id,
        target_name=vp.name,
        ip=client_ip(request),
        project_id=vp.project_id,
    )


@router.post("/encrypt", response_model=VaultEncryptResponse)
def encrypt(
    payload: VaultEncryptRequest,
    request: Request,
    actor: User = Depends(_encrypt_guard),
    db: Session = Depends(get_db),
) -> VaultEncryptResponse:
    vault_password, password = _load_password(
        db, actor, request, payload.vault_password_id, Permission.VAULT_ENCRYPT
    )
    try:
        envelope = encrypt_to_vault_envelope(payload.plaintext, password)
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Encryption failed: {exc}") from exc
    _audit_use(db, "vault.encrypt", actor, request, vault_password)
    return VaultEncryptResponse(
        vault_text=envelope, yaml_block=to_yaml_block(envelope, payload.var_name)
    )


@router.post("/decrypt", response_model=VaultDecryptResponse)
def decrypt(
    payload: VaultDecryptRequest,
    request: Request,
    actor: User = Depends(_decrypt_guard),
    db: Session = Depends(get_db),
) -> VaultDecryptResponse:
    vault_password, password = _load_password(
        db, actor, request, payload.vault_password_id, Permission.VAULT_DECRYPT
    )
    try:
        plaintext = decrypt_vault_text(payload.ciphertext, password)
    except VaultError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Decryption failed: {exc}") from exc
    _audit_use(db, "vault.decrypt", actor, request, vault_password)
    return VaultDecryptResponse(plaintext=plaintext)
