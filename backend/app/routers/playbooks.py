import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import GitSnapshot, GitSource, Playbook, User
from app.permissions import Permission, Scope, guard
from app.schemas.playbooks import PlaybookCreate, PlaybookDetail, PlaybookSummary, PlaybookUpdate
from app.scoping import get_scoped, readable_project_ids, resolve_write_project
from app.storage import playbook_path

_guard = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


class _PlaybookLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Ansible's `!vault` tag (inline-encrypted values)."""


_PlaybookLoader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))


def _validate_yaml(content: str) -> None:
    try:
        yaml.load(content, Loader=_PlaybookLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid YAML: {exc}") from exc


def _git_info(db: Session, playbooks: list[Playbook]) -> dict[int, tuple[str, str | None]]:
    """{source id: (name, current commit)} for the synced playbooks among `playbooks`."""
    ids = {p.source_id for p in playbooks if p.source_id is not None}
    if not ids:
        return {}
    rows = db.execute(
        select(GitSource.id, GitSource.name, GitSnapshot.commit)
        .outerjoin(GitSnapshot, GitSnapshot.id == GitSource.current_snapshot_id)
        .where(GitSource.id.in_(ids))
    ).all()
    return {source_id: (name, commit) for source_id, name, commit in rows}


def _summary(playbook: Playbook, git: dict[int, tuple[str, str | None]]) -> dict:
    name, commit = git.get(playbook.source_id, (None, None))
    return {
        "id": playbook.id,
        "name": playbook.name,
        "project_id": playbook.project_id,
        "created_at": playbook.created_at,
        "updated_at": playbook.updated_at,
        "source_id": playbook.source_id,
        "source_name": name,
        "repo_path": playbook.repo_path,
        "commit": commit,
        "missing_at": playbook.missing_at,
    }


def _to_detail(db: Session, playbook: Playbook, content: str) -> PlaybookDetail:
    return PlaybookDetail(**_summary(playbook, _git_info(db, [playbook])), content=content)


def _read_only(db: Session, playbook: Playbook) -> HTTPException:
    source = db.get(GitSource, playbook.source_id)
    return HTTPException(
        status.HTTP_409_CONFLICT,
        f"This playbook is synced from git source {source.name!r}: change it in the repository",
    )


@router.get("", response_model=list[PlaybookSummary])
def list_playbooks(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[dict]:
    ids = readable_project_ids(db, user, request, Permission.CONTENT_READ, project_id)
    query = db.query(Playbook)
    if ids is not None:
        query = query.filter(Playbook.project_id.in_(ids))
    playbooks = query.order_by(Playbook.name).all()
    git = _git_info(db, playbooks)
    return [_summary(playbook, git) for playbook in playbooks]


@router.post("", response_model=PlaybookDetail, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: PlaybookCreate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> PlaybookDetail:
    project_id = resolve_write_project(
        db, user, request, payload.project_id, Permission.CONTENT_WRITE
    )
    _validate_yaml(payload.content)
    playbook = Playbook(name=payload.name, project_id=project_id)
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    playbook_path(playbook.id).write_text(payload.content)
    return _to_detail(db, playbook, payload.content)


@router.get("/{playbook_id}", response_model=PlaybookDetail)
def get_playbook(
    playbook_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> PlaybookDetail:
    playbook = get_scoped(
        db, user, request, Playbook, playbook_id, Permission.CONTENT_READ, "Playbook not found"
    )
    return _to_detail(db, playbook, playbook_path(playbook_id).read_text())


@router.put("/{playbook_id}", response_model=PlaybookDetail)
def update_playbook(
    playbook_id: int,
    payload: PlaybookUpdate,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> PlaybookDetail:
    playbook = get_scoped(
        db, user, request, Playbook, playbook_id, Permission.CONTENT_WRITE, "Playbook not found"
    )
    if playbook.source_id is not None:
        raise _read_only(db, playbook)
    if payload.content is not None:
        _validate_yaml(payload.content)
        playbook_path(playbook_id).write_text(payload.content)
    if payload.name is not None:
        playbook.name = payload.name
    db.commit()
    db.refresh(playbook)
    return _to_detail(db, playbook, playbook_path(playbook_id).read_text())


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(
    playbook_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    playbook = get_scoped(
        db, user, request, Playbook, playbook_id, Permission.CONTENT_WRITE, "Playbook not found"
    )
    if playbook.source_id is not None and playbook.missing_at is None:
        raise _read_only(db, playbook)  # only once it is gone upstream
    db.delete(playbook)
    db.commit()
    playbook_path(playbook_id).unlink(missing_ok=True)
