from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.crypto import encrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import Credential, User
from app.permissions import Permission, Scope, guard
from app.schemas.credentials import CredentialCreate, CredentialOut
from app.scoping import get_scoped, readable_project_ids, resolve_write_project

_guard = guard(Permission.SECRETS_LIST, Permission.SECRETS_MANAGE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


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
def list_credentials(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[Credential]:
    ids = readable_project_ids(db, user, request, Permission.SECRETS_LIST, project_id)
    query = db.query(Credential)
    if ids is not None:
        query = query.filter(Credential.project_id.in_(ids))
    return query.order_by(Credential.name).all()


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(
    payload: CredentialCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> Credential:
    project_id = resolve_write_project(
        db, actor, request, payload.project_id, Permission.SECRETS_MANAGE
    )
    key_bytes = payload.private_key.encode()
    _validate_private_key(key_bytes)

    credential = Credential(
        name=payload.name,
        description=payload.description,
        encrypted_private_key=encrypt_secret(key_bytes),
        project_id=project_id,
    )
    db.add(credential)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Credential name already exists") from exc
    db.refresh(credential)
    audit.record(
        db,
        "credential.create",
        actor=actor,
        target_type="credential",
        target_id=credential.id,
        target_name=credential.name,
        ip=client_ip(request),
        project_id=credential.project_id,
    )
    return credential


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(
    credential_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    credential = get_scoped(
        db,
        actor,
        request,
        Credential,
        credential_id,
        Permission.SECRETS_MANAGE,
        "Credential not found",
    )
    name, project_id = credential.name, credential.project_id
    db.delete(credential)
    db.commit()
    audit.record(
        db,
        "credential.delete",
        actor=actor,
        target_type="credential",
        target_id=credential_id,
        target_name=name,
        ip=client_ip(request),
        project_id=project_id,
    )
