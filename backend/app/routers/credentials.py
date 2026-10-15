import json
from typing import Literal

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, secret_store, ssh_certificates
from app.config import get_settings
from app.crypto import decrypt_secret, encrypt_secret
from app.db import get_db
from app.env_credentials import encrypt_env, env_problem
from app.hardening import FailureThrottle, client_ip
from app.models import Credential, GitSource, InventorySource, User
from app.permissions import Permission, Scope, guard
from app.schemas.credentials import (
    CredentialCreate,
    CredentialOut,
    MoveToStore,
    ReferenceUpdate,
    SecretCheck,
)
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
        "ssh_mount": credential.ssh_mount,
        "ssh_role": credential.ssh_role,
        "ssh_role_full": (
            secret_store.ssh_role_name(credential.project_id, credential.ssh_role)
            if credential.ssh_role
            else None
        ),
        "ssh_principals": credential.ssh_principals,
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
    kind: list[Literal["ssh", "env", "ssh_cert"]] | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    ids = readable_project_ids(db, user, request, Permission.SECRETS_LIST, project_id)
    query = db.query(Credential)
    if ids is not None:
        query = query.filter(Credential.project_id.in_(ids))
    if kind:
        query = query.filter(Credential.kind.in_(kind))
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
    elif payload.kind == "ssh_cert":
        credential, detail = _new_ssh_cert_credential(payload, project_id)
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


def _new_ssh_cert_credential(payload: CredentialCreate, project_id: int) -> tuple[Credential, dict]:
    """Checks the settings and has the store sign a throwaway key once (as a reference is read
    once), so a role that doesn't exist or doesn't allow the principals is caught now."""
    settings = get_settings()
    mounts = settings.secrets_store_ssh_mount_list
    try:
        mount = ssh_certificates.check_mount(payload.ssh_mount or (mounts[0] if mounts else ""))
        role = ssh_certificates.check_role(payload.ssh_role)
        principals = ssh_certificates.check_principals(payload.ssh_principals)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    credential = Credential(
        name=payload.name,
        description=payload.description,
        kind="ssh_cert",
        ssh_mount=mount,
        ssh_role=role,
        ssh_principals=principals,
        project_id=project_id,
    )
    location = secret_store.ssh_location(project_id, mount, role)
    try:
        info = ssh_certificates.sign_test_certificate(credential)
    except SecretStoreError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{settings.secrets_store_label}: {secret_store.explain(exc.kind)} ({location})",
        ) from None
    return credential, {
        "kind": "ssh_cert",
        "location": location,
        "principals": principals,
        "test_serial": info["serial"],
    }


def edit_reference(
    db: Session, actor: User, request: Request, row, payload: ReferenceUpdate, kind: str, check
):
    """Points a row's store reference elsewhere once `check(project_id, path, key)` read it
    (400 when it can't be; returns what to audit besides the locations). The row is locked
    and must still point where it did, so a concurrent edit isn't overwritten. Queued runs
    read the new reference when they start."""
    label = get_settings().secrets_store_label
    if getattr(row, "kind", None) == "ssh_cert":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "An SSH certificate credential has no reference to edit"
        )
    if row.store_path is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This {kind.replace('_', ' ')} is stored in AnsiDeck, not {label}",
        )
    env = getattr(row, "kind", None) == "env"
    if env and payload.store_key is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "An env credential reads the whole secret: no store_key"
        )
    model, row_id, project_id = type(row), row.id, row.project_id
    before = (row.store_path, row.store_key)
    path = payload.store_path or before[0]
    key = None if env else payload.store_key or before[1]
    throttled_check(actor)
    db.rollback()  # no transaction held open while the store answers
    detail = check(project_id, path, key)
    row = db.get(model, row_id, with_for_update=True, populate_existing=True)
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"{kind.replace('_', ' ').capitalize()} not found"
        )
    if (row.store_path, row.store_key) != before:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Its reference changed while this one was checked; try again"
        )
    row.store_path, row.store_key = path, key
    db.commit()
    audit.record(
        db,
        f"{kind}.reference_update",
        actor=actor,
        target_type=kind,
        target_id=row.id,
        target_name=row.name,
        ip=client_ip(request),
        project_id=project_id,
        detail={
            "location_before": secret_store.location(project_id, *before),
            "location": secret_store.location(project_id, path, key),
            **detail,
        },
    )
    return row


def move_to_store(
    db: Session,
    actor: User,
    request: Request,
    row,
    payload: MoveToStore,
    kind: str,
    field: str,
    values,
):
    """Writes a secret stored here into the store and keeps a reference instead (opt-in:
    SECRETS_STORE_ALLOW_MOVE). The store only ever gets a new secret (check-and-set 0, after
    a read finds nothing there), which is read back and compared before the copy here is
    dropped; the row is locked and must be unchanged. `values(row)` gives the secret's keys
    and values; `field` is the encrypted column that goes."""
    settings = get_settings()
    label = settings.secrets_store_label
    noun = kind.replace("_", " ")
    if not secret_store.enabled() or not settings.secrets_store_allow_move:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Moving secrets to {label} is off (SECRETS_STORE_ALLOW_MOVE)"
        )
    if getattr(row, "kind", None) == "ssh_cert" or row.store_path is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"This {noun} is already in {label}")
    env = getattr(row, "kind", None) == "env"
    if env and payload.store_key is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Each variable becomes a key of the secret: no store_key"
        )
    model, row_id, project_id, path = type(row), row.id, row.project_id, payload.store_path
    key = (
        None
        if env
        else payload.store_key or ("password" if kind == "vault_password" else "private_key")
    )
    try:
        secret_store.check_path(path)
        if key is not None:
            secret_store.check_key(key)
    except SecretStoreError as exc:
        raise _store_error(project_id, path, key, exc) from None
    ciphertext = getattr(row, field)
    data = values(row)
    target = {"target_type": kind, "target_id": row_id, "target_name": row.name}
    throttled_check(actor)
    db.rollback()  # no transaction held open while the store answers
    location = secret_store.location(project_id, path, key)

    def failed(code: int, message: str, error_kind: str, **detail) -> HTTPException:
        audit.record(
            db,
            f"{kind}.move_to_store",
            outcome="failure",
            actor=actor,
            ip=client_ip(request),
            project_id=project_id,
            detail={"location": location, "error_kind": error_kind, **detail},
            **target,
        )
        return HTTPException(code, message)

    try:  # a secret already there (even one AnsiDeck can't read) is never touched
        secret_store.read_all_versioned(project_id, path)
    except SecretStoreError as exc:
        if exc.kind != "not_found":
            raise _store_error(project_id, path, key, exc) from None
    else:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{label} already has a secret at {secret_store.location(project_id, path, None)}: "
            "choose another path",
        )
    try:
        version = secret_store.create_secret(project_id, path, data)
    except SecretStoreError as exc:
        code = status.HTTP_409_CONFLICT if exc.kind == "exists" else status.HTTP_400_BAD_REQUEST
        raise failed(
            code, f"{label}: {secret_store.explain(exc.kind)} ({location})", exc.kind
        ) from None
    try:
        back, back_version = secret_store.read_all_versioned(project_id, path)
        matches = back == data and back_version == version
    except SecretStoreError:
        matches = False
    if not matches:
        raise failed(
            status.HTTP_502_BAD_GATEWAY,
            f"{label} took the secret (version {version} at {location}) but reading it back "
            "didn't give the same value; nothing changed here. Check it in "
            f"{label}, and delete it there if it is wrong.",
            "read_back",
            version=version,
        )
    row = db.get(model, row_id, with_for_update=True, populate_existing=True)
    if row is None or row.store_path is not None or getattr(row, field) != ciphertext:
        db.rollback()
        raise failed(
            status.HTTP_409_CONFLICT,
            f"The {noun} changed or was deleted while it was moved; nothing changed here. "
            f"{label} has the old value at {location} (version {version}): delete it there.",
            "changed",
            version=version,
        )
    row.store_path, row.store_key = path, key
    setattr(row, field, None)
    if env:
        row.env_names = None  # whatever keys the secret has
    db.commit()
    audit.record(
        db,
        f"{kind}.move_to_store",
        actor=actor,
        ip=client_ip(request),
        project_id=project_id,
        detail={
            "location": location,
            "version": version,
            **({"names": sorted(data)} if env else {}),
        },
        **target,
    )
    return row


@router.post("/{credential_id}/move-to-store", response_model=CredentialOut)
def move_credential_to_store(
    credential_id: int,
    payload: MoveToStore,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Moves a key or variables stored here into the secret store (see move_to_store)."""
    credential = get_scoped(
        db, actor, request, Credential, credential_id, Permission.SECRETS_MANAGE,
        "Credential not found",
    )  # fmt: skip
    if credential.kind == "env":
        field = "encrypted_env"

        def values(row) -> dict[str, str]:
            return json.loads(decrypt_secret(row.encrypted_env))
    else:
        field = "encrypted_private_key"

        def values(row) -> dict[str, str]:
            key = payload.store_key or "private_key"
            return {key: decrypt_secret(row.encrypted_private_key).decode()}

    moved = move_to_store(db, actor, request, credential, payload, "credential", field, values)
    return _out(moved)


@router.patch("/{credential_id}", response_model=CredentialOut)
def update_credential_reference(
    credential_id: int,
    payload: ReferenceUpdate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> dict:
    """Points a credential in the secret store at another path or key (read once to check)."""
    credential = get_scoped(
        db, actor, request, Credential, credential_id, Permission.SECRETS_MANAGE,
        "Credential not found",
    )  # fmt: skip

    def check(project_id: int, path: str, key: str | None) -> dict:
        if key is None:
            names, version = read_env_reference(project_id, path)
            return {"names": names, "version": version}
        value, version = read_reference(project_id, path, key)
        _validate_private_key(value.encode())
        return {"version": version}

    return _out(edit_reference(db, actor, request, credential, payload, "credential", check))


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
    if credential.kind == "ssh_cert":
        return check_ssh_certificate(db, actor, request, credential)
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


def check_ssh_certificate(db: Session, actor: User, request: Request, credential) -> dict:
    """Has the store sign a throwaway key with the credential's role, and audits the check
    with the test certificate's serial."""
    target = {
        "target_id": credential.id,
        "target_name": credential.name,
        "project_id": credential.project_id,
    }
    db.expunge(credential)  # read its fields after the rollback below
    db.rollback()  # no transaction held open while the store answers
    try:
        info = ssh_certificates.sign_test_certificate(credential)
        result: dict = {"ok": True, "certificate": info}
    except SecretStoreError as exc:
        result = {"ok": False, "error_kind": exc.kind, "error": secret_store.explain(exc.kind)}
    audit.record(
        db,
        "credential.check",
        outcome="success" if result["ok"] else "failure",
        actor=actor,
        target_type="credential",
        ip=client_ip(request),
        detail=(
            {"serial": result["certificate"]["serial"]}
            if result["ok"]
            else {"error_kind": result["error_kind"]}
        ),
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
    used_by = (
        db.query(InventorySource).filter(InventorySource.credential_id == credential_id).first()
    )
    if used_by is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Inventory source {used_by.name!r} uses this credential"
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
