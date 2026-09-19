import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Playbook, User
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


def _to_detail(playbook: Playbook, content: str) -> PlaybookDetail:
    return PlaybookDetail(
        id=playbook.id,
        name=playbook.name,
        project_id=playbook.project_id,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        content=content,
    )


@router.get("", response_model=list[PlaybookSummary])
def list_playbooks(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[Playbook]:
    ids = readable_project_ids(db, user, request, Permission.CONTENT_READ, project_id)
    query = db.query(Playbook)
    if ids is not None:
        query = query.filter(Playbook.project_id.in_(ids))
    return query.order_by(Playbook.name).all()


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
    return _to_detail(playbook, payload.content)


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
    return _to_detail(playbook, playbook_path(playbook_id).read_text())


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
    if payload.content is not None:
        _validate_yaml(payload.content)
        playbook_path(playbook_id).write_text(payload.content)
    if payload.name is not None:
        playbook.name = payload.name
    db.commit()
    db.refresh(playbook)
    return _to_detail(playbook, playbook_path(playbook_id).read_text())


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
    db.delete(playbook)
    db.commit()
    playbook_path(playbook_id).unlink(missing_ok=True)
