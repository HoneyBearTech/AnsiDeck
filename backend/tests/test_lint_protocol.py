"""Playbook checks over the internal API (Phase 5B-2), with the test playing the worker:
claims by kind, the one-time job, the per-person and global limits, results, the reaper, the
galaxy gate and snapshot pinning."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from app.config import get_settings
from app.db import get_sessionmaker
from app.galaxy import try_start_install
from app.git_sync import prune_snapshots
from app.lint import prune_lint_jobs
from app.models import GalaxyInstall, GitSnapshot, LintJob, RunStatus
from app.reaper import reap_once
from tests.conftest import internal_client, make_user_client
from tests.test_git_sources import local_git  # noqa: F401 - fixture
from tests.test_runs import _login

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves

UNTIDY = "- hosts: all\n  tasks:\n    - shell: echo hi\n"
FINDING = {
    "rule": "fqcn[action-core]",
    "level": "error",
    "message": "Use FQCN for builtin module actions (shell).",
    "details": None,
    "path": "playbook.yml",
    "line": 3,
    "column": 7,
    "url": "https://docs.ansible.com/projects/lint/rules/fqcn/",
}


def _check(client: TestClient, content: str = UNTIDY) -> dict:
    response = client.post("/api/playbooks/lint", json={"content": content})
    assert response.status_code == 202, response.text
    return response.json()


def _row(lint_id: int) -> LintJob:
    db = get_sessionmaker()()
    try:
        return db.get(LintJob, lint_id)
    finally:
        db.close()


class ClaimedLint:
    def __init__(self, worker: str = "w") -> None:
        self.http = internal_client()
        claim = self.http.post(
            "/internal/claim", json={"worker_id": worker, "wait_seconds": 0, "kinds": ["lint"]}
        )
        assert claim.status_code == 200, claim.text
        body = claim.json()
        assert body["kind"] == "lint"
        self.id, self.claim_token, self.job_token = (
            body["run_id"],
            body["claim_token"],
            body["job_token"],
        )

    def post(self, action: str, body: dict, claim_token: str | None = None):
        return self.http.post(
            f"/internal/lints/{self.id}/{action}",
            json=body,
            headers={"X-Claim-Token": claim_token or self.claim_token},
        )

    def job(self):
        return self.post("job", {"job_token": self.job_token})

    def complete(self, **body):
        return self.post("complete", {"status": "success", **body})


def _nothing_to_claim(kinds=("lint",)) -> bool:
    response = internal_client().post(
        "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "kinds": list(kinds)}
    )
    return response.status_code == 204


def test_only_workers_that_ask_for_checks_get_them(client: TestClient) -> None:
    _login(client)
    _check(client)
    assert _nothing_to_claim(("run", "refresh"))  # a worker from before 5B never gets one
    claimed = ClaimedLint()
    assert _row(claimed.id).status == "running"


def test_the_job_is_handed_out_once_with_the_text(client: TestClient) -> None:
    _login(client)
    queued = _check(client)
    assert queued["status"] == "queued"
    assert queued["target"] == "playbook.yml"
    claimed = ClaimedLint()
    assert claimed.post("job", {"job_token": "wrong"}).status_code == 410
    job = claimed.job()
    assert job.status_code == 200, job.text
    assert job.json() == {
        "kind": "lint",
        "content": UNTIDY,
        "project": None,
        "target": "playbook.yml",
        "secrets": [],
        "timeout_seconds": get_settings().lint_timeout_seconds,
        "max_findings": 500,
    }
    assert claimed.job().status_code == 410  # once
    assert claimed.post("job", {"job_token": claimed.job_token}, "wrong").status_code == 410


def test_findings_are_stored_for_the_requester_and_the_text_is_dropped(client: TestClient) -> None:
    _login(client)
    queued = _check(client)
    claimed = ClaimedLint()
    claimed.job()
    other = {**FINDING, "path": "roles/web/tasks/main.yml", "line": 1, "column": None}
    done = claimed.complete(
        findings=[FINDING, other], total=3, truncated=True, external=1, version="26.9.0"
    )
    assert done.status_code == 200, done.text
    result = client.get(f"/api/lint-jobs/{queued['id']}").json()
    assert result["status"] == "success"
    assert result["findings"] == [{**FINDING, "in_target": True}, {**other, "in_target": False}]
    assert (result["total"], result["truncated"], result["external"]) == (3, True, 1)
    assert result["ansible_lint_version"] == "26.9.0"
    assert result["wait_reason"] is None
    row = _row(queued["id"])
    assert row.content is None
    assert row.claim_token_hash is None
    assert claimed.complete().status_code == 410  # the claim ended


def test_a_failed_check_keeps_its_reason(client: TestClient) -> None:
    _login(client)
    queued = _check(client)
    claimed = ClaimedLint()
    claimed.job()
    claimed.post("complete", {"status": "failed", "error": "ansible-lint failed (exit 1): boom"})
    result = client.get(f"/api/lint-jobs/{queued['id']}").json()
    assert (result["status"], result["error"]) == ("failed", "ansible-lint failed (exit 1): boom")
    assert result["findings"] == []


@pytest.mark.parametrize(
    "bad",
    [
        {"findings": [{**FINDING, "url": "javascript:alert(1)"}]},
        {"findings": [{**FINDING, "line": 0}]},
        {"findings": [{**FINDING, "level": "info"}]},
        {"findings": [{**FINDING, "message": "x" * 501}]},
        {"findings": [FINDING] * 501},
    ],
    ids=["url-scheme", "line-zero", "level", "long-message", "too-many"],
)
def test_untrusted_results_are_validated(client: TestClient, bad: dict) -> None:
    _login(client)
    _check(client)
    claimed = ClaimedLint()
    claimed.job()
    assert claimed.complete(**bad).status_code == 422


def test_a_newer_check_replaces_the_queued_one(client: TestClient) -> None:
    _login(client)
    first = _check(client, "- hosts: a\n")
    second = _check(client, "- hosts: b\n")
    assert client.get(f"/api/lint-jobs/{first['id']}").json()["status"] == "cancelled"
    replaced = _row(first["id"])
    assert (replaced.status, replaced.error, replaced.content) == (
        "cancelled",
        "replaced by a newer check",
        None,
    )
    claimed = ClaimedLint()
    assert claimed.id == second["id"]
    assert claimed.job().json()["content"] == "- hosts: b\n"


def test_one_running_check_per_person_and_a_global_cap(client: TestClient, monkeypatch) -> None:
    _login(client)
    _check(client)
    ClaimedLint()
    waiting = _check(client)
    assert _nothing_to_claim()  # this person already has one running
    assert client.get(f"/api/lint-jobs/{waiting['id']}").json()["wait_reason"] == (
        "Waiting for your previous check to finish"
    )

    monkeypatch.setenv("LINT_MAX_RUNNING", "1")
    get_settings.cache_clear()
    try:
        someone = make_user_client("checker", "operator")
        theirs = _check(someone)
        assert _nothing_to_claim()  # the one running check is the cap
        monkeypatch.setenv("LINT_MAX_RUNNING", "2")
        get_settings.cache_clear()
        assert ClaimedLint().id == theirs["id"]
    finally:
        get_settings.cache_clear()


def test_the_reaper_ends_lost_overrunning_and_unclaimed_checks(client: TestClient) -> None:
    _login(client)
    lost = _check(client)
    ClaimedLint()
    db = get_sessionmaker()()
    db.execute(
        update(LintJob)
        .where(LintJob.id == lost["id"])
        .values(lease_expires_at=text("now() - interval '1 second'"))
    )
    db.commit()
    reap_once()
    row = _row(lost["id"])
    assert row.status == "failed"
    assert row.error.startswith("worker lost: no heartbeat from w since ")

    overrun = _check(client)
    ClaimedLint()
    db.execute(
        update(LintJob)
        .where(LintJob.id == overrun["id"])
        .values(claimed_at=text("now() - interval '1 hour'"))
    )
    db.commit()
    reap_once()
    assert _row(overrun["id"]).status == "timed_out"

    stale = _check(client)
    db.execute(
        update(LintJob)
        .where(LintJob.id == stale["id"])
        .values(queued_at=text("now() - interval '10 minutes'"))
    )
    db.commit()
    reap_once()
    row = _row(stale["id"])
    assert row.status == "failed"
    # its claims above made worker "w" count as online, with nothing running now
    assert row.error == "not checked: Waiting for a worker…"

    db.execute(update(LintJob).values(finished_at=text("now() - interval '2 hours'")))
    db.commit()
    assert prune_lint_jobs(db) == 3
    db.commit()
    db.close()
    assert client.get(f"/api/lint-jobs/{stale['id']}").status_code == 404


def test_heartbeats_renew_a_check_and_say_when_it_is_gone(client: TestClient) -> None:
    _login(client)
    _check(client)
    claimed = ClaimedLint()
    beat = internal_client().post(
        "/internal/heartbeat",
        json={
            "worker_id": "w",
            "runs": [],
            "lints": [
                {"lint_id": claimed.id, "claim_token": claimed.claim_token},
                {"lint_id": claimed.id + 999, "claim_token": "x"},
            ],
        },
    )
    assert beat.json()["lints"] == [
        {"lint_id": claimed.id, "state": "ok"},
        {"lint_id": claimed.id + 999, "state": "gone"},
    ]


def test_galaxy_installs_and_checks_wait_for_each_other(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr("app.galaxy.run_install", lambda install_id: None)
    _login(client)
    _check(client)
    claimed = ClaimedLint()
    db = get_sessionmaker()()
    install = GalaxyInstall(
        status=RunStatus.QUEUED.value, triggered_by="admin", requirements_snapshot=""
    )
    db.add(install)
    db.commit()
    assert try_start_install() is None  # a check is running: ansible-lint loads collections
    claimed.job()
    claimed.complete()
    assert _row(claimed.id).status == "success"
    assert db.get(GalaxyInstall, install.id, populate_existing=True).status == "running"
    db.close()
    _check(client)
    assert _nothing_to_claim()  # nothing is claimed while an install runs


def test_checks_are_private_to_whoever_asked(client: TestClient) -> None:
    _login(client)
    mine = _check(client)
    operator = make_user_client("op2", "operator")
    assert operator.get(f"/api/lint-jobs/{mine['id']}").status_code == 404
    theirs = _check(operator)
    assert client.get(f"/api/lint-jobs/{theirs['id']}").status_code == 404  # even an admin
    assert operator.get(f"/api/lint-jobs/{theirs['id']}").status_code == 200
    viewer = make_user_client("viewer2", "viewer")
    assert viewer.post("/api/playbooks/lint", json={"content": UNTIDY}).status_code == 403


def test_limits_on_what_can_be_checked(client: TestClient) -> None:
    _login(client)
    too_big = client.post("/api/playbooks/lint", json={"content": "#" * (1024 * 1024 + 1)})
    assert too_big.status_code == 413
    assert "over 1024 KiB" in too_big.json()["detail"]
    assert client.post("/api/playbooks/lint", json={"content": "a: [\n"}).status_code == 202


def test_a_snapshot_pinned_by_a_check_is_not_pruned(
    client: TestClient,
    local_git,  # noqa: F811 - fixture
    tmp_path,
) -> None:
    from tests.test_lint_jobs import synced_playbook

    _login(client)
    playbook_id, source_id = synced_playbook(client, tmp_path)
    queued = client.post(f"/api/playbooks/{playbook_id}/lint")
    assert queued.status_code == 202, queued.text
    snapshot_id = _row(queued.json()["id"]).git_snapshot_id
    db = get_sessionmaker()()
    db.execute(
        update(GitSnapshot)
        .where(GitSnapshot.id == snapshot_id)
        .values(superseded_at=text("now() - interval '1 day'"))
    )
    db.execute(
        text("UPDATE git_sources SET current_snapshot_id = NULL WHERE id = :id"), {"id": source_id}
    )
    db.commit()
    prune_snapshots(db)
    assert db.get(GitSnapshot, snapshot_id) is not None
    db.execute(update(LintJob).values(status="success"))
    db.commit()
    prune_snapshots(db)
    assert db.get(GitSnapshot, snapshot_id, populate_existing=True) is None
    db.close()
