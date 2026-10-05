from datetime import datetime

from pydantic import BaseModel, Field


class LintContentIn(BaseModel):
    # Checked as it is, unsaved and even invalid YAML: that's what the check reports on.
    content: str
    # The project whose Galaxy content and workers it uses; omitted when only one qualifies.
    project_id: int | None = None


class LintFindingOut(BaseModel):
    rule: str
    level: str  # "error" | "warning"
    message: str
    details: str | None = None
    path: str
    line: int
    column: int | None = None
    url: str | None = None
    # In the file that was checked (else a role or tasks file it includes).
    in_target: bool


class LintJobOut(BaseModel):
    id: int
    status: str  # queued | running | success | failed | timed_out | cancelled
    target: str
    playbook_id: int | None
    commit: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    # Why a queued check hasn't started.
    wait_reason: str | None = None
    error: str | None
    findings: list[LintFindingOut] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False
    # Findings in files outside the project (an installed collection), left out.
    external: int = 0
    # The repository's own ansible-lint config was used (else ansible-lint's default rules).
    repo_config: bool = False
    # A secret's value appeared in a finding and was redacted.
    scrubbed: bool = False
    ansible_lint_version: str | None = None
