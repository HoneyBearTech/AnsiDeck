"""Playbook checks end to end (Phase 5B-2): the API queues them, the in-process worker runs
the real ansible-lint in its run process and the requester polls the findings."""

import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import git_sync
from app.db import get_sessionmaker
from app.models import Playbook
from tests.test_git_sources import _create, local_git, make_repo  # noqa: F401 - fixture
from tests.test_runs import _create_playbook, _login

UNTIDY = "- hosts: all\n  tasks:\n    - shell: echo hi\n"
REPO = {
    "site.yml": "- name: Site\n  hosts: all\n  roles:\n    - web\n",
    "roles/web/tasks/main.yml": "- shell: echo {{ db_password }} hunter2-repo-secret\n",
    "group_vars/all.yml": "db_password: hunter2-repo-secret\n",
    ".ansible-lint": "skip_list:\n  - name[missing]\nwrite_list:\n  - all\n",
}


def synced_playbook(
    client: TestClient, tmp_path: Path, files: dict | None = None
) -> tuple[int, int]:
    """(the id of a playbook synced from a local repository, its source's id)."""
    repo = make_repo(tmp_path / "repo", files or REPO)
    source = _create(client, repo)
    assert git_sync.sync_source(source["id"]) == "ok"
    db = get_sessionmaker()()
    try:
        playbook_id = db.scalar(
            select(Playbook.id).where(
                Playbook.source_id == source["id"], Playbook.repo_path == "site.yml"
            )
        )
    finally:
        db.close()
    return playbook_id, source["id"]


def _wait(client: TestClient, lint_id: int, timeout: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = client.get(f"/api/lint-jobs/{lint_id}").json()
        if result["status"] not in ("queued", "running"):
            return result
        time.sleep(0.25)
    raise AssertionError(f"check {lint_id} did not finish within {timeout}s")


def _rules(result: dict) -> set[str]:
    return {f["rule"] for f in result["findings"]}


def test_unsaved_text_is_checked_by_a_worker(client: TestClient) -> None:
    _login(client)
    queued = client.post("/api/playbooks/lint", json={"content": UNTIDY})
    assert queued.status_code == 202, queued.text
    result = _wait(client, queued.json()["id"])
    assert result["status"] == "success", result
    assert {"name[play]", "fqcn[action-core]", "no-changed-when"} <= _rules(result)
    fqcn = next(f for f in result["findings"] if f["rule"] == "fqcn[action-core]")
    assert (fqcn["line"], fqcn["column"], fqcn["in_target"]) == (3, 7, True)
    assert result["repo_config"] is False
    assert result["ansible_lint_version"]


def test_a_saved_playbook_is_checked_by_id(client: TestClient) -> None:
    _login(client)
    playbook_id = _create_playbook(client, UNTIDY)
    queued = client.post(f"/api/playbooks/{playbook_id}/lint")
    assert queued.status_code == 202, queued.text
    assert queued.json()["playbook_id"] == playbook_id
    assert "fqcn[action-core]" in _rules(_wait(client, queued.json()["id"]))


def test_a_synced_playbook_is_checked_in_its_repository(
    client: TestClient,
    local_git,  # noqa: F811 - fixture
    tmp_path,
) -> None:
    _login(client)
    playbook_id, _source = synced_playbook(client, tmp_path)
    queued = client.post(f"/api/playbooks/{playbook_id}/lint").json()
    assert queued["target"] == "site.yml"
    assert len(queued["commit"]) == 40
    result = _wait(client, queued["id"])
    assert result["status"] == "success", result
    assert result["repo_config"] is True
    rules = _rules(result)
    assert "name[missing]" not in rules  # the repository's skip_list
    assert {"fqcn[action-core]", "command-instead-of-shell"} <= rules  # write_list ignored
    assert {f["path"] for f in result["findings"]} == {"roles/web/tasks/main.yml"}
    assert all(not f["in_target"] for f in result["findings"])
    # The repository's secret-looking variable never comes back in a finding.
    assert "hunter2-repo-secret" not in str(result)
    assert result["scrubbed"] is True


def test_a_synced_playbook_gone_upstream_cannot_be_checked(
    client: TestClient,
    local_git,  # noqa: F811 - fixture
    tmp_path,
) -> None:
    _login(client)
    playbook_id, _source = synced_playbook(client, tmp_path)
    db = get_sessionmaker()()
    db.execute(
        update(Playbook).where(Playbook.id == playbook_id).values(missing_at=Playbook.created_at)
    )
    db.commit()
    db.close()
    refused = client.post(f"/api/playbooks/{playbook_id}/lint")
    assert refused.status_code == 409
    assert "no longer in its git repository" in refused.json()["detail"]
