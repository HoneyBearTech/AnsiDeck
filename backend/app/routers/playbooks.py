import logging

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.lint import CONTENT_TARGET, MAX_LINT_CONTENT_BYTES, enqueue_lint
from app.models import GitSnapshot, GitSource, LintJob, Playbook, User
from app.notify import notifier
from app.permissions import Permission, Scope, guard
from app.queue import QUEUE_TOPIC
from app.routers.lint import lint_out
from app.routers.runs import pin_snapshot
from app.schemas.lint import LintContentIn, LintJobOut
from app.schemas.playbooks import PlaybookCreate, PlaybookDetail, PlaybookSummary, PlaybookUpdate
from app.scoping import get_scoped, readable_project_ids, resolve_write_project
from app.storage import playbook_path

logger = logging.getLogger(__name__)

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
    return _to_detail(db, playbook, playbook_path(playbook.id).read_text())


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
        playbook_path(playbook.id).write_text(payload.content)
    if payload.name is not None:
        playbook.name = payload.name
    db.commit()
    db.refresh(playbook)
    return _to_detail(db, playbook, playbook_path(playbook.id).read_text())


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
    playbook_path(playbook.id).unlink(missing_ok=True)


# --- playbook checks (Phase 5B) -------------------------------------------------------------


def _too_large(content: str) -> None:
    if len(content.encode()) > MAX_LINT_CONTENT_BYTES:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"The playbook is too large to check (over {MAX_LINT_CONTENT_BYTES // 1024} KiB)",
        )


def _queued(db: Session, lint: LintJob) -> LintJobOut:
    try:
        db.commit()
    except IntegrityError as exc:  # another check of yours was queued at the same moment
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Another check of yours is being queued: try again"
        ) from exc
    db.refresh(lint)
    logger.info("check %s queued by %s (%s)", lint.id, lint.requested_by, lint.target)
    notifier.notify(QUEUE_TOPIC)  # wake the workers waiting for a claim
    return lint_out(db, lint)


@router.post("/lint", response_model=LintJobOut, status_code=status.HTTP_202_ACCEPTED)
def lint_content(
    payload: LintContentIn,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> LintJobOut:
    """Checks text with ansible-lint (unsaved, even invalid YAML) in a worker, with the
    Galaxy collections and roles. Poll GET /api/lint-jobs/{id} for the findings."""
    project_id = resolve_write_project(
        db, user, request, payload.project_id, Permission.CONTENT_WRITE
    )
    _too_large(payload.content)
    lint = enqueue_lint(db, user, project_id, target=CONTENT_TARGET, content=payload.content)
    return _queued(db, lint)


@router.post("/{playbook_id}/lint", response_model=LintJobOut, status_code=status.HTTP_202_ACCEPTED)
def lint_playbook(
    playbook_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> LintJobOut:
    """Checks a saved playbook; one synced from git inside its repository at the source's
    current commit, with the repository's own ansible-lint config, roles and collections."""
    playbook = get_scoped(
        db, user, request, Playbook, playbook_id, Permission.CONTENT_WRITE, "Playbook not found"
    )
    if playbook.source_id is not None:
        git = pin_snapshot(db, playbook)["columns"]
        lint = enqueue_lint(
            db,
            user,
            playbook.project_id,
            target=git["playbook_path"],
            playbook_id=playbook.id,
            snapshot_id=git["git_snapshot_id"],
            commit=git["git_commit"],
        )
    else:
        content = playbook_path(playbook.id).read_text(encoding="utf-8")
        _too_large(content)
        lint = enqueue_lint(
            db, user, playbook.project_id, target=CONTENT_TARGET, content=content,
            playbook_id=playbook.id,
        )  # fmt: skip
    return _queued(db, lint)
