from typing import Literal

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, secret_store
from app.config import get_settings
from app.crypto import encrypt_secret
from app.db import get_db
from app.env_credentials import encrypt_env, env_problem
from app.hardening import FailureThrottle, client_ip
from app.models import Credential, GitSource, User
from app.permissions import Permission, Scope, guard
from app.schemas.credentials import CredentialCreate, CredentialOut, SecretCheck
from app.scoping import get_scoped, readable_project_ids, resolve_write_project
from app.secret_store import SecretStoreError

# Reading the secret store on demand ("Test"): at most 10 a minute per user.
check_throttle = FailureThrottle(max_failures=10, window_seconds=60)

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


def _out(credential: Credential) -> dict:
    return {
        "id": credential.id,
        "name": credential.name,
        "description": credential.description,
        "project_id": credential.project_id,
        "created_at": credential.created_at,
        "kind": credential.kind,
        "env_names": credential.env_names,
        **secret_store.reference_fields(credential),
    }


def _store_error(project_id: int, path: str, key: str | None, exc: SecretStoreError):
    where = (
        secret_store.location(project_id, path, key) if exc.kind != "invalid" else "that reference"
    )
    return HTTPException(
        status.HTTP_400_BAD_REQUEST,
        f"{get_settings().secrets_store_label}: {secret_store.explain(exc.kind)} ({where})",
    )


def read_reference(project_id: int, path: str, key: str) -> tuple[str, int]:
    """A new reference's value (for validating it), or 400 with what went wrong."""
    if not secret_store.enabled():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No secret store is configured")
    try:
        return secret_store.read_versioned(project_id, path, key)
    except SecretStoreError as exc:
        raise _store_error(project_id, path, key, exc) from None


def read_env_reference(project_id: int, path: str) -> tuple[list[str], int]:
    """A new env reference's variable names (its values are checked, never kept)."""
    if not secret_store.enabled():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No secret store is configured")
    try:
        data, version = secret_store.read_all_versioned(project_id, path)
    except SecretStoreError as exc:
        raise _store_error(project_id, path, None, exc) from None
    if problem := env_problem(data):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"The secret's keys can't be used: {problem}"
        )
    return sorted(data), version


def throttled_check(user: User) -> None:
    if check_throttle.blocked(user.id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many checks; wait a minute")
    check_throttle.record_failure(user.id)  # every check counts


@router.get("", response_model=list[CredentialOut])
def list_credentials(
    request: Request,
    project_id: int | None = Query(None),
    kind: Literal["ssh", "env"] | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    ids = readable_project_ids(db, user, request, Permission.SECRETS_LIST, project_id)
    query = db.query(Credential)
    if ids is not None:
        query = query.filter(Credential.project_id.in_(ids))
    if kind is not None:
        query = query.filter(Credential.kind == kind)
    return [_out(credential) for credential in query.order_by(Credential.name).all()]


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(
    payload: CredentialCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    project_id = resolve_write_project(
        db, actor, request, payload.project_id, Permission.SECRETS_MANAGE
    )
    detail: dict | None = None
    if payload.kind == "env":
        credential, detail = _new_env_credential(payload, project_id)
    elif payload.store_path is not None:
        # Read once to check it is there and is a key; never stored here.
        value, version = read_reference(project_id, payload.store_path, payload.store_key)
        _validate_private_key(value.encode())
        del value
        credential = Credential(
            name=payload.name,
            description=payload.description,
            store_path=payload.store_path,
            store_key=payload.store_key,
            project_id=project_id,
        )
        detail = {
            "store": "external",
            "location": secret_store.location(project_id, payload.store_path, payload.store_key),
            "version": version,
        }
    else:
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
        detail=detail,
    )
    return _out(credential)


def _new_env_credential(payload: CredentialCreate, project_id: int) -> tuple[Credential, dict]:
    if payload.store_path is not None:
        names, version = read_env_reference(project_id, payload.store_path)
        credential = Credential(
            name=payload.name,
            description=payload.description,
            kind="env",
            store_path=payload.store_path,
            project_id=project_id,
        )
        return credential, {
            "kind": "env",
            "store": "external",
            "location": secret_store.location(project_id, payload.store_path, None),
            "names": names,
            "version": version,
        }
    if problem := env_problem(payload.env):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)
    env = dict(payload.env)
    credential = Credential(
        name=payload.name,
        description=payload.description,
        kind="env",
        encrypted_env=encrypt_env(env),
        env_names=sorted(env),
        project_id=project_id,
    )
    return credential, {"kind": "env", "names": sorted(env)}


@router.post("/{credential_id}/check", response_model=SecretCheck)
def check_credential(
    credential_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Whether the key can be read now (from the secret store); never returns it."""
    credential = get_scoped(
        db, actor, request, Credential, credential_id, Permission.SECRETS_MANAGE,
        "Credential not found",
    )  # fmt: skip
    throttled_check(actor)
    if credential.kind == "env":
        return check_env_reference(db, actor, request, credential)
    return check_reference(
        db, actor, request, credential, "credential", validate=_validate_private_key_text
    )


def check_env_reference(db: Session, actor: User, request: Request, credential) -> dict:
    """Like check_reference, for an env credential: reports the variable names it holds."""
    target = {
        "target_id": credential.id,
        "target_name": credential.name,
        "project_id": credential.project_id,
    }
    project_id, path = credential.project_id, credential.store_path
    names = credential.env_names
    db.rollback()  # no transaction held open while the store answers
    result: dict = {"ok": True, "env_names": names}
    if path is not None:
        try:
            data, version = secret_store.read_all_versioned(project_id, path)
        except SecretStoreError as exc:
            result = {"ok": False, "error_kind": exc.kind, "error": secret_store.explain(exc.kind)}
        else:
            if problem := env_problem(data):
                result = {"ok": False, "error_kind": "bad_value", "error": problem}
            else:
                result.update(version=version, env_names=sorted(data))
    audit.record(
        db,
        "credential.check",
        outcome="success" if result["ok"] else "failure",
        actor=actor,
        target_type="credential",
        ip=client_ip(request),
        detail=None if result["ok"] else {"error_kind": result["error_kind"]},
        **target,
    )
    return result


def _validate_private_key_text(value: str) -> None:
    _validate_private_key(value.encode())


def check_reference(db: Session, actor: User, request: Request, row, kind: str, validate) -> dict:
    """Reads a credential's or vault password's stored secret now (never returning it) and
    audits the check. AnsiDeck-stored secrets are always readable."""
    target = {"target_id": row.id, "target_name": row.name, "project_id": row.project_id}
    reference = (row.project_id, row.store_path, row.store_key)
    db.rollback()  # no transaction held open while the store answers
    result: dict = {"ok": True}
    if reference[1] is not None:
        try:
            value, version = secret_store.read_versioned(*reference)
            validate(value)
            result["version"] = version
        except SecretStoreError as exc:
            result = {"ok": False, "error_kind": exc.kind, "error": secret_store.explain(exc.kind)}
        except HTTPException:
            result = {
                "ok": False,
                "error_kind": "bad_value",
                "error": f"the value is not a {kind.replace('_', ' ')} value",
            }
    audit.record(
        db,
        f"{kind}.check",
        outcome="success" if result["ok"] else "failure",
        actor=actor,
        target_type=kind,
        ip=client_ip(request),
        detail=None if result["ok"] else {"error_kind": result["error_kind"]},
        **target,
    )
    return result


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
    source = db.query(GitSource).filter(GitSource.credential_id == credential_id).first()
    if source is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Git source {source.name!r} uses this key as its deploy key"
        )
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
