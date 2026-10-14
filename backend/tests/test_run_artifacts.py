"""Run artifacts: files a playbook leaves in ARTIFACTS_DIR, kept with the run (regular files
only, within the limits), listed for anyone who sees the run, downloadable with runs:trigger,
checked on the way in and deleted after the retention."""

import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from app.config import get_settings
from app.db import get_engine, get_sessionmaker
from app.main import app
from app.models import Run
from app.reaper import prune_artifacts
from app.run_worker import collect_artifacts
from app.storage import run_artifacts_path
from tests.conftest import internal_client, make_user_client
from tests.test_runs import (
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
)

PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.copy:
        content: "all good\\n"
        dest: "{{ ansideck_artifacts_dir }}/report.txt"
    - ansible.builtin.file:
        path: "{{ lookup('env', 'ARTIFACTS_DIR') }}/sub"
        state: directory
    - ansible.builtin.copy:
        content: '{"hosts": 1}'
        dest: "{{ ansideck_artifacts_dir }}/sub/data.json"
    - ansible.builtin.file:
        src: /etc/passwd
        dest: "{{ ansideck_artifacts_dir }}/passwd"
        state: link
"""


def _start(client: TestClient, tmp_path, playbook: str = PLAYBOOK) -> dict:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, playbook, name="art.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    )
    assert run.status_code == 201, run.text
    return _wait_for_completion(client, run.json()["id"], timeout=60)


def test_a_run_keeps_the_files_it_left_and_only_runners_download_them(client, tmp_path):
    run = _start(client, tmp_path)
    assert run["status"] == "success", run["status_reason"]
    assert run["artifacts_count"] == 2 and run["artifacts_error"] is None
    listed = client.get(f"/api/runs/{run['id']}/artifacts").json()
    assert listed["files"] == [
        {"path": "report.txt", "size": 9},
        {"path": "sub/data.json", "size": 12},
    ]  # the link to /etc/passwd was not followed
    assert listed["can_download"] is True

    tar = client.get(f"/api/runs/{run['id']}/artifacts/download")
    assert tar.status_code == 200 and tar.headers["content-type"] == "application/gzip"
    with tarfile.open(fileobj=io.BytesIO(tar.content), mode="r:gz") as archive:
        assert sorted(archive.getnames()) == ["artifacts/report.txt", "artifacts/sub/data.json"]
    one = client.get(f"/api/runs/{run['id']}/artifacts/file", params={"path": "sub/data.json"})
    assert one.content == b'{"hosts": 1}'
    assert 'filename="data.json"' in one.headers["content-disposition"]
    missing = client.get(f"/api/runs/{run['id']}/artifacts/file", params={"path": "passwd"})
    assert missing.status_code == 404

    viewer = make_user_client("viewer1", "viewer")
    seen = viewer.get(f"/api/runs/{run['id']}/artifacts").json()
    assert len(seen["files"]) == 2 and seen["can_download"] is False
    assert viewer.get(f"/api/runs/{run['id']}/artifacts/download").status_code == 403

    # CI: a trigger key downloads them, a read-only key only lists them.
    for preset, code in (("trigger", 200), ("read-only", 403)):
        token = client.post(
            "/api/projects/1/api-keys",
            json={"name": f"ci-{preset}", "preset": preset, "current_password": "admin"},
        ).json()["token"]
        key = TestClient(app, headers={"Authorization": f"Bearer {token}"})
        assert key.get(f"/api/runs/{run['id']}/artifacts").status_code == 200
        assert key.get(f"/api/runs/{run['id']}/artifacts/download").status_code == code


def test_too_many_files_are_not_kept_and_the_run_still_counts(client, tmp_path, monkeypatch):
    monkeypatch.setenv("RUN_ARTIFACT_MAX_FILES", "1")
    get_settings.cache_clear()
    run = _start(client, tmp_path)
    assert run["status"] == "success"
    assert run["artifacts_count"] == 0
    assert run["artifacts_error"] == "more than 1 files in ARTIFACTS_DIR: none were kept"
    assert client.get(f"/api/runs/{run['id']}/artifacts/download").status_code == 404


def test_old_artifacts_are_deleted_but_still_listed(client, tmp_path) -> None:
    run = _start(client, tmp_path)
    path = run_artifacts_path(run["id"])
    assert path.is_file()
    with get_engine().begin() as conn:
        conn.execute(update(Run).values(finished_at=text("now() - interval '31 days'")))
    with get_sessionmaker()() as db:
        assert prune_artifacts(db, 30) == 1
        assert prune_artifacts(db, 30) == 0
    assert not path.exists()
    listed = client.get(f"/api/runs/{run['id']}/artifacts").json()
    assert listed["deleted_at"] is not None and len(listed["files"]) == 2
    assert client.get(f"/api/runs/{run['id']}/artifacts/download").status_code == 404


@pytest.mark.no_worker
def test_artifacts_that_dont_match_what_the_worker_says_are_refused(client, tmp_path) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    run_id = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, PLAYBOOK, name="x.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    ).json()["id"]
    http = internal_client()
    claim = http.post(
        "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "host_keys": True}
    ).json()
    token = {"X-Claim-Token": claim["claim_token"]}
    job = http.post(
        f"/internal/runs/{run_id}/job", json={"job_token": claim["job_token"]}, headers=token
    ).json()
    assert job["artifacts"]["max_files"] == 1000
    data = b"not really a tar"
    uploaded = http.post(
        f"/internal/runs/{run_id}/artifacts", content=data, headers={**token, "X-Offset": "0"}
    )
    assert uploaded.json() == {"offset": len(data)}
    gap = http.post(
        f"/internal/runs/{run_id}/artifacts", content=b"x", headers={**token, "X-Offset": "99"}
    )
    assert gap.status_code == 409 and gap.json() == {"expected_offset": len(data)}
    body = {
        "last_seq": 0,
        "status": "success",
        "return_code": 0,
        "artifacts": {
            "files": [{"path": "a", "size": 1}],
            "bytes": 1,
            "tar_bytes": len(data),
            "sha256": hashlib.sha256(b"something else").hexdigest(),
        },
    }
    assert http.post(f"/internal/runs/{run_id}/complete", json=body, headers=token).json() == {}
    row = client.get(f"/api/runs/{run_id}").json()
    assert row["artifacts_error"] == "the artifacts didn't arrive intact"
    assert not run_artifacts_path(run_id).exists()


def test_collection_takes_regular_files_within_the_limits(tmp_path: Path) -> None:
    root = tmp_path / "ansideck-artifacts"
    (root / "d").mkdir(parents=True)
    (root / "a.txt").write_text("abc")
    (root / "d" / "b.bin").write_bytes(b"\x00" * 10)
    os.symlink("/etc/hostname", root / "link")
    os.symlink(tmp_path, root / "dirlink")
    os.mkfifo(root / "fifo")
    found = collect_artifacts(tmp_path, 1024, 10)
    assert found["files"] == [{"path": "a.txt", "size": 3}, {"path": "d/b.bin", "size": 10}]
    assert found["bytes"] == 13
    with tarfile.open(found["tar"]) as tar:
        member = tar.getmember("artifacts/a.txt")
        assert member.mode == 0o644 and member.uid == 0
    assert collect_artifacts(tmp_path, 12, 10) == {
        "error": "over 12 bytes in ARTIFACTS_DIR: none were kept"
    }
    (root / "a.txt").unlink()
    (root / "d" / "b.bin").unlink()
    assert collect_artifacts(tmp_path, 1024, 10) == {}
