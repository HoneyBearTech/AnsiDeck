"""Playbook checks (Phase 5B): ansible-lint over an editor's text or a synced playbook's
repository, run by a worker like an inventory refresh (claim, lease, one-time job token) and
reported back as findings. A check is private to whoever asked for it, each person has at most
one queued and one running, and finished checks are pruned after an hour (app.reaper)."""

import hashlib
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app import metrics
from app.config import get_settings
from app.git_sync import snapshot_path, vars_texts
from app.models import GitSnapshot, InventoryRefresh, LintJob, Run, RunStatus, User
from app.queue import install_pending, online_slots
from app.scrub import collect_secrets

MAX_LINT_CONTENT_BYTES = 1024 * 1024  # as a run's playbook snapshot
MAX_FINDINGS = 500
CONTENT_TARGET = "playbook.yml"
# A check nobody claims in this long fails with the reason it waited (e.g. only workers from
# before 5B, which never take checks).
QUEUE_TIMEOUT_SECONDS = 120
RETENTION_SECONDS = 3600
TIMEOUT_GRACE_SECONDS = 30
CANCELLED = "cancelled"


class LintJobError(Exception):
    """The check can't be handed to a worker (its message is safe to show)."""


def enqueue_lint(
    db: Session,
    user: User,
    project_id: int,
    *,
    target: str,
    content: str | None = None,
    playbook_id: int | None = None,
    snapshot_id: int | None = None,
    commit: str | None = None,
) -> LintJob:
    """Queues a check, replacing the person's queued one (the newer text wins). The caller
    commits, then wakes the workers (QUEUE_TOPIC)."""
    replaced = db.execute(
        update(LintJob)
        .where(
            LintJob.requested_by_user_id == user.id,
            LintJob.status == RunStatus.QUEUED.value,
        )
        .values(
            status=CANCELLED,
            error="replaced by a newer check",
            content=None,
            finished_at=func.now(),
        )
        .returning(LintJob.id)
    ).all()
    for _ in replaced:
        metrics.lint_finished(CANCELLED, None)
    lint = LintJob(
        project_id=project_id,
        requested_by_user_id=user.id,
        requested_by=user.username,
        playbook_id=playbook_id,
        target=target,
        content=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest()
        if content is not None
        else None,
        git_snapshot_id=snapshot_id,
        git_commit=commit,
        status=RunStatus.QUEUED.value,
        timeout_seconds=get_settings().lint_timeout_seconds,
    )
    db.add(lint)
    db.flush()
    return lint


def build_lint_job(db: Session, lint: LintJob) -> dict:
    """What the worker needs: the text, or the repository's size and hash (it downloads the
    tar), and the values to scrub from findings (a repository's secret-looking variables)."""
    project = None
    repo_vars: list[str] = []
    if lint.git_commit is not None:
        snapshot = db.get(GitSnapshot, lint.git_snapshot_id) if lint.git_snapshot_id else None
        if snapshot is None or not snapshot_path(snapshot).is_file():
            raise LintJobError("the repository snapshot is gone: check again")
        if snapshot_path(snapshot).stat().st_size != snapshot.size_bytes:
            raise LintJobError("the repository snapshot on disk changed")
        project = {"playbook": lint.target, "bytes": snapshot.size_bytes, "sha256": snapshot.sha256}
        repo_vars = vars_texts(snapshot)
    secrets = collect_secrets(
        ssh_key_pem="",
        vault_password=None,
        playbook_text=lint.content or "",
        extra_vars=None,
        host_vars=[],
        repo_vars_texts=repo_vars,
    )
    return {
        "kind": "lint",
        "content": lint.content,
        "project": project,
        "target": lint.target,
        "secrets": sorted(s for s in secrets if s),
        "timeout_seconds": lint.timeout_seconds,
        "max_findings": MAX_FINDINGS,
    }


def end_lint(
    lint: LintJob,
    status: str,
    *,
    error: str | None = None,
    result: dict | None = None,
) -> None:
    """Records the outcome; the text and the claim go. The caller holds the row lock and
    commits."""
    lint.status = status
    lint.finished_at = func.now()
    lint.lease_expires_at = None
    lint.claim_token_hash = None
    lint.job_token_hash = None
    lint.job_token_expires_at = None
    lint.content = None
    lint.error = error[:1000] if error else None
    if result is not None:
        lint.findings = result["findings"]
        lint.findings_total = result["total"]
        lint.truncated = result["truncated"]
        lint.external = result["external"]
        lint.repo_config = result["repo_config"]
        lint.scrubbed = result["scrubbed"]
        lint.ansible_lint_version = result["version"]
    started = lint.started_at if isinstance(lint.started_at, datetime) else None
    metrics.lint_finished(
        status, (datetime.now(UTC) - started).total_seconds() if started else None
    )


def wait_reason(db: Session, lint: LintJob) -> str:
    """Why a queued check hasn't started yet, in the claim rules' order."""
    if install_pending(db):
        return "Waiting for a Galaxy install to finish"
    running = LintJob.status == RunStatus.RUNNING.value
    mine = db.scalar(
        select(LintJob.id)
        .where(running, LintJob.requested_by_user_id == lint.requested_by_user_id)
        .limit(1)
    )
    if mine is not None:
        return "Waiting for your previous check to finish"
    slots = online_slots(db)
    if slots == 0:
        return "No worker is online: start one to check playbooks"
    checks = db.scalar(select(func.count()).where(running))
    limit = get_settings().lint_max_running
    if checks >= limit:
        return f"Waiting: {checks} checks are running (at most {limit} at once)"
    busy = (
        checks
        + db.scalar(select(func.count()).where(Run.status == RunStatus.RUNNING.value))
        + db.scalar(select(func.count()).where(InventoryRefresh.status == RunStatus.RUNNING.value))
    )
    if busy >= slots:
        return "Waiting for a free worker (all are busy)"
    return "Waiting for a worker…"


def prune_lint_jobs(db: Session) -> int:
    """Deletes checks that ended over RETENTION_SECONDS ago (the caller commits)."""
    cutoff = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, RETENTION_SECONDS)
    return len(
        db.execute(
            delete(LintJob)
            .where(LintJob.finished_at.is_not(None), LintJob.finished_at < cutoff)
            .returning(LintJob.id)
        ).all()
    )
