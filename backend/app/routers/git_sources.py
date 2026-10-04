"""A project's git sources (Phase 4E). Project admins manage them (sources:manage: URL,
deploy key or token, trusted host key); anyone who may edit content can ask for a sync;
everyone in the project sees them. Not for API keys."""

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, git_sync
from app.crypto import encrypt_secret
from app.db import get_db
from app.hardening import client_ip
from app.models import Credential, GitSnapshot, GitSource, Playbook, Run, RunStatus, User
from app.notify import notifier
from app.permissions import Permission, Scope, guard
from app.schemas.git_sources import (
    GitSourceCreate,
    GitSourceOut,
    GitSourceUpdate,
    SnapshotOut,
    TestResult,
    TrustHostKey,
)
from app.scoping import require_project_permission

router = APIRouter()

# Reads: anyone in the project. Changes: project admins (sources:manage). The guard is the
# coarse "somewhere" check; every handler then checks the project in the path.
_manage = guard(Permission.CONTENT_READ, Permission.SOURCES_MANAGE, scope=Scope.PROJECT)
_sync = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)

MAX_SOURCES_PER_PROJECT = 20
_WEB_URL = re.compile(r"^https?://[^\s<>\"']+$")


def _load(db: Session, project_id: int, source_id: int) -> GitSource:
    source = db.get(GitSource, source_id)
    if source is None or source.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Git source not found")
    return source


def _host_keys(source: GitSource) -> list[dict]:
    keys = []
    for line in (source.ssh_known_hosts or "").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                keys.append({"type": parts[1], "fingerprint": git_sync.fingerprint(parts[2])})
            except ValueError:
                continue
    return keys


def _out(db: Session, source: GitSource) -> dict:
    snapshot = (
        db.get(GitSnapshot, source.current_snapshot_id) if source.current_snapshot_id else None
    )
    credential = db.get(Credential, source.credential_id) if source.credential_id else None
    counts = dict(
        db.execute(
            select(Playbook.missing_at.is_(None), func.count())
            .where(Playbook.source_id == source.id)
            .group_by(Playbook.missing_at.is_(None))
        ).all()
    )
    return {
        "id": source.id,
        "project_id": source.project_id,
        "name": source.name,
        "url": source.url,
        "branch": source.branch,
        "subdir": source.subdir,
        "web_url": source.web_url,
        "playbook_globs": source.playbook_globs or git_sync.DEFAULT_GLOBS,
        "auth_kind": source.auth_kind,
        "credential_id": source.credential_id,
        "credential_name": credential.name if credential else None,
        "https_username": source.https_username,
        "has_token": source.encrypted_token is not None,
        "host_keys": _host_keys(source),
        "auto_sync_seconds": source.auto_sync_seconds,
        "enabled": source.enabled,
        "commit": snapshot.commit if snapshot else None,
        "commit_subject": snapshot.commit_subject if snapshot else None,
        "committed_at": snapshot.committed_at if snapshot else None,
        "warnings": snapshot.warnings if snapshot else [],
        "playbooks": counts.get(True, 0),
        "missing_playbooks": counts.get(False, 0),
        "sync_requested_at": source.sync_requested_at,
        "last_sync_started_at": source.last_sync_started_at,
        "last_sync_finished_at": source.last_sync_finished_at,
        "last_sync_status": source.last_sync_status,
        "last_sync_error": source.last_sync_error,
        "created_by": source.created_by,
        "created_at": source.created_at,
    }


def _bad(message: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, message)


def _apply_settings(db: Session, source: GitSource, values: dict, *, creating: bool) -> None:
    """Validates and applies create/update fields. A new host clears the trusted key."""
    old_alias = None
    if not creating:
        try:
            old_alias = git_sync.parse_url(source.url).host_key_alias
        except git_sync.SyncError:
            old_alias = None
    try:
        if "url" in values:
            git_sync.parse_url(values["url"])
            source.url = values["url"].strip()
        if "branch" in values:
            source.branch = git_sync.check_branch(values["branch"])
        if "subdir" in values:
            source.subdir = git_sync.check_subdir(values["subdir"])
        if values.get("playbook_globs") is not None:
            source.playbook_globs = git_sync.check_globs(values["playbook_globs"])
        remote = git_sync.parse_url(source.url)
    except git_sync.SyncError as exc:
        raise _bad(str(exc)) from exc
    if "web_url" in values:
        web_url = (values["web_url"] or "").strip().rstrip("/") or None
        if web_url and not _WEB_URL.match(web_url):
            raise _bad("the web URL must start with https:// or http://")
        source.web_url = web_url
    for key in ("name", "auto_sync_seconds", "enabled", "auth_kind"):
        if values.get(key) is not None:
            setattr(source, key, values[key].strip() if key == "name" else values[key])

    if remote.kind == "ssh":
        if source.auth_kind != "ssh_key":
            raise _bad("ssh sources need an SSH deploy key (auth: ssh_key)")
    elif source.auth_kind == "ssh_key":
        raise _bad("SSH keys work with ssh:// or user@host:path URLs only")
    if source.auth_kind == "ssh_key":
        credential_id = values.get("credential_id", source.credential_id)
        credential = db.get(Credential, credential_id) if credential_id is not None else None
        if credential is None or credential.project_id != source.project_id:
            raise _bad("pick an SSH key (credential) of this project")
        source.credential_id = credential.id
    else:
        source.credential_id = None
    if source.auth_kind == "https_token":
        if values.get("token"):
            source.encrypted_token = encrypt_secret(values["token"].encode())
        if source.encrypted_token is None:
            raise _bad("an HTTPS token source needs a token")
        if "https_username" in values:
            source.https_username = (values["https_username"] or "").strip() or None
    else:
        source.encrypted_token = None
        source.https_username = None
    new_alias = remote.host_key_alias if remote.kind == "ssh" else None
    if old_alias != new_alias:
        source.ssh_known_hosts = None  # trust belongs to a host


def _audit(db: Session, action: str, user: User, request: Request, source: GitSource, **detail):
    audit.record(
        db,
        action,
        actor=user,
        target_type="git_source",
        target_id=source.id,
        target_name=source.name,
        ip=client_ip(request),
        project_id=source.project_id,
        detail=detail or None,
    )


def _request_sync(source: GitSource) -> None:
    source.sync_requested_at = func.now()


@router.get("", response_model=list[GitSourceOut])
def list_sources(
    project_id: int, request: Request, user: User = Depends(_manage), db: Session = Depends(get_db)
) -> list[dict]:
    require_project_permission(db, user, request, project_id, Permission.CONTENT_READ)
    sources = db.scalars(
        select(GitSource).where(GitSource.project_id == project_id).order_by(GitSource.name)
    ).all()
    return [_out(db, source) for source in sources]


@router.post("", response_model=GitSourceOut, status_code=status.HTTP_201_CREATED)
def create_source(
    project_id: int,
    payload: GitSourceCreate,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.SOURCES_MANAGE)
    if (
        db.scalar(select(func.count()).where(GitSource.project_id == project_id))
        >= MAX_SOURCES_PER_PROJECT
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "This project has too many git sources")
    source = GitSource(
        project_id=project_id,
        name=payload.name.strip(),
        url=payload.url.strip(),
        playbook_globs=git_sync.DEFAULT_GLOBS,
        created_by=user.username,
    )
    _apply_settings(db, source, payload.model_dump(), creating=True)
    if source.auth_kind != "ssh_key":
        _request_sync(source)  # ssh sources wait for a trusted host key
    db.add(source)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A git source with that name already exists"
        ) from exc
    db.refresh(source)
    _audit(db, "git_source.create", user, request, source, url=source.url, branch=source.branch)
    notifier.notify(git_sync.SYNC_TOPIC)
    return _out(db, source)


@router.get("/{source_id}", response_model=GitSourceOut)
def get_source(
    project_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.CONTENT_READ)
    return _out(db, _load(db, project_id, source_id))


@router.patch("/{source_id}", response_model=GitSourceOut)
def update_source(
    project_id: int,
    source_id: int,
    payload: GitSourceUpdate,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.SOURCES_MANAGE)
    source = _load(db, project_id, source_id)
    values = payload.model_dump(exclude_unset=True)
    _apply_settings(db, source, values, creating=False)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A git source with that name already exists"
        ) from exc
    changed = sorted(k for k in values if k != "token") + (["token"] if values.get("token") else [])
    _audit(db, "git_source.update", user, request, source, changed=changed)
    return _out(db, source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(
    project_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> None:
    require_project_permission(db, user, request, project_id, Permission.SOURCES_MANAGE)
    source = _load(db, project_id, source_id)
    active = db.scalar(
        select(func.count()).where(
            Run.git_source_id == source.id,
            Run.status.in_((RunStatus.QUEUED.value, RunStatus.RUNNING.value)),
        )
    )
    if active:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Runs from this source are queued or running; wait for them"
        )
    playbook_ids = list(db.scalars(select(Playbook.id).where(Playbook.source_id == source.id)))
    name = source.name
    db.delete(source)  # its playbooks and snapshots cascade; runs keep their name snapshot
    db.commit()
    git_sync.remove_files(source_id, playbook_ids)
    audit.record(
        db,
        "git_source.delete",
        actor=user,
        target_type="git_source",
        target_id=source_id,
        target_name=name,
        ip=client_ip(request),
        project_id=project_id,
        detail={"playbooks": len(playbook_ids)},
    )


@router.get("/{source_id}/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    project_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> list[dict]:
    require_project_permission(db, user, request, project_id, Permission.CONTENT_READ)
    source = _load(db, project_id, source_id)
    snapshots = db.scalars(
        select(GitSnapshot)
        .where(GitSnapshot.source_id == source.id)
        .order_by(GitSnapshot.created_at.desc())
        .limit(20)
    ).all()
    return [
        {
            "commit": s.commit,
            "commit_subject": s.commit_subject,
            "commit_author": s.commit_author,
            "committed_at": s.committed_at,
            "size_bytes": s.size_bytes,
            "file_count": s.file_count,
            "warnings": s.warnings,
            "created_at": s.created_at,
            "superseded_at": s.superseded_at,
            "current": s.id == source.current_snapshot_id,
        }
        for s in snapshots
    ]


@router.post("/{source_id}/test", response_model=TestResult)
def test_source(
    project_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    """Checks the connection: for ssh the host key first (shown for an admin to trust),
    then whether the branch exists. No transaction is held while it talks to the server."""
    require_project_permission(db, user, request, project_id, Permission.SOURCES_MANAGE)
    source = _load(db, project_id, source_id)
    branch = source.branch
    trusted = {
        line.split()[2]
        for line in (source.ssh_known_hosts or "").splitlines()
        if len(line.split()) >= 3
    }
    try:
        remote = git_sync.parse_url(source.url)
        auth = git_sync.auth_for(db, source)
    except git_sync.SyncError as exc:
        return {"ok": False, "error": str(exc)}
    db.rollback()  # nothing held open during network calls
    result: dict = {"ok": False}
    try:
        if remote.kind == "ssh":
            keys = git_sync.keyscan(remote)
            result["host_keys"] = [
                {"type": k["type"], "fingerprint": k["fingerprint"], "trusted": k["key"] in trusted}
                for k in keys
            ]
            result["host_key_trusted"] = any(k["key"] in trusted for k in keys)
            if not result["host_key_trusted"]:
                result["error"] = "Trust the server's host key to connect"
                return result
        info = git_sync.ls_remote(remote, auth, branch)
    except git_sync.SyncError as exc:
        result["error"] = str(exc)
        return result
    result.update(info)
    result["ok"] = info["branch_exists"]
    if not info["branch_exists"]:
        result["error"] = f"Branch {branch!r} not found"
    return result


@router.post("/{source_id}/trust-host-key", response_model=GitSourceOut)
def trust_host_key(
    project_id: int,
    source_id: int,
    payload: TrustHostKey,
    request: Request,
    user: User = Depends(_manage),
    db: Session = Depends(get_db),
) -> dict:
    """Trusts the server key with the fingerprint an admin confirmed (scanned again now), or
    pasted known_hosts lines. Replaces any earlier trust."""
    require_project_permission(db, user, request, project_id, Permission.SOURCES_MANAGE)
    source = _load(db, project_id, source_id)
    try:
        remote = git_sync.parse_url(source.url)
        if remote.kind != "ssh":
            raise _bad("only ssh sources have host keys")
        if payload.known_hosts:
            known_hosts = git_sync.parse_known_hosts(remote, payload.known_hosts)
        elif payload.fingerprint:
            db.rollback()
            keys = [k for k in git_sync.keyscan(remote) if k["fingerprint"] == payload.fingerprint]
            if not keys:
                raise _bad("the server doesn't present a key with that fingerprint")
            known_hosts = "".join(
                git_sync.known_hosts_line(remote, k["type"], k["key"]) + "\n" for k in keys
            )
        else:
            raise _bad("give a fingerprint or known_hosts lines")
    except git_sync.SyncError as exc:
        raise _bad(str(exc)) from exc
    source = _load(db, project_id, source_id)
    source.ssh_known_hosts = known_hosts
    _request_sync(source)
    db.commit()
    _audit(
        db,
        "git_source.trust_host_key",
        user,
        request,
        source,
        fingerprints=[k["fingerprint"] for k in _host_keys(source)],
    )
    notifier.notify(git_sync.SYNC_TOPIC)
    return _out(db, source)


@router.post("/{source_id}/sync", status_code=status.HTTP_202_ACCEPTED)
def request_sync(
    project_id: int,
    source_id: int,
    request: Request,
    user: User = Depends(_sync),
    db: Session = Depends(get_db),
) -> dict:
    require_project_permission(db, user, request, project_id, Permission.CONTENT_WRITE)
    source = _load(db, project_id, source_id)
    if not source.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "This source is turned off")
    _request_sync(source)
    db.commit()
    notifier.notify(git_sync.SYNC_TOPIC)
    return {"queued": True}
