"""Playbook check results (Phase 5B). Started from the playbooks routes; private to whoever
asked (a check of unsaved text can echo it), so another person, even an admin, gets 404."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.lint import CONTENT_TARGET, wait_reason
from app.models import LintJob, RunStatus, User
from app.permissions import Permission, Scope, guard, project_permissions
from app.schemas.lint import LintJobOut

_guard = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)
router = APIRouter(dependencies=[Depends(_guard)])


def lint_out(db: Session, lint: LintJob) -> LintJobOut:
    findings = [
        {**finding, "in_target": finding.get("path") == lint.target}
        for finding in lint.findings or []
    ]
    return LintJobOut(
        id=lint.id,
        status=lint.status,
        target=lint.target if lint.git_commit is not None else CONTENT_TARGET,
        playbook_id=lint.playbook_id,
        commit=lint.git_commit,
        queued_at=lint.queued_at,
        started_at=lint.started_at,
        finished_at=lint.finished_at,
        wait_reason=wait_reason(db, lint) if lint.status == RunStatus.QUEUED.value else None,
        error=lint.error,
        findings=findings,
        total=lint.findings_total or 0,
        truncated=lint.truncated,
        external=lint.external,
        repo_config=lint.repo_config,
        scrubbed=lint.scrubbed,
        ansible_lint_version=lint.ansible_lint_version,
    )


@router.get("/{lint_id}", response_model=LintJobOut)
def get_lint_job(
    lint_id: int,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> LintJobOut:
    lint = db.get(LintJob, lint_id)
    if (
        lint is None
        or lint.requested_by_user_id != user.id
        or not project_permissions(db, user, lint.project_id)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Check not found")
    return lint_out(db, lint)
