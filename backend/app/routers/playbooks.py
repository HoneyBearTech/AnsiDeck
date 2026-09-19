import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Playbook
from app.schemas.playbooks import PlaybookCreate, PlaybookDetail, PlaybookSummary, PlaybookUpdate
from app.storage import playbook_path

router = APIRouter(dependencies=[Depends(get_current_user)])


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
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        content=content,
    )


@router.get("", response_model=list[PlaybookSummary])
def list_playbooks(db: Session = Depends(get_db)) -> list[Playbook]:
    return db.query(Playbook).order_by(Playbook.name).all()


@router.post("", response_model=PlaybookDetail, status_code=status.HTTP_201_CREATED)
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)) -> PlaybookDetail:
    _validate_yaml(payload.content)
    playbook = Playbook(name=payload.name)
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    playbook_path(playbook.id).write_text(payload.content)
    return _to_detail(playbook, payload.content)


@router.get("/{playbook_id}", response_model=PlaybookDetail)
def get_playbook(playbook_id: int, db: Session = Depends(get_db)) -> PlaybookDetail:
    playbook = db.get(Playbook, playbook_id)
    if playbook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    return _to_detail(playbook, playbook_path(playbook_id).read_text())


@router.put("/{playbook_id}", response_model=PlaybookDetail)
def update_playbook(
    playbook_id: int, payload: PlaybookUpdate, db: Session = Depends(get_db)
) -> PlaybookDetail:
    playbook = db.get(Playbook, playbook_id)
    if playbook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    if payload.content is not None:
        _validate_yaml(payload.content)
        playbook_path(playbook_id).write_text(payload.content)
    if payload.name is not None:
        playbook.name = payload.name
    db.commit()
    db.refresh(playbook)
    return _to_detail(playbook, playbook_path(playbook_id).read_text())


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(playbook_id: int, db: Session = Depends(get_db)) -> None:
    playbook = db.get(Playbook, playbook_id)
    if playbook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    db.delete(playbook)
    db.commit()
    playbook_path(playbook_id).unlink(missing_ok=True)
