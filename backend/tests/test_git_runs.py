"""Runs of playbooks synced from git (Phase 4E-2): a run executes inside its repository at
the commit pinned when it was triggered, with the repository's roles, templates, vars and
ansible.cfg; the worker gets that exact tar, and the run's process unpacks it safely."""

import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import git_sync, run_worker
from app.db import get_sessionmaker
from app.models import GitSnapshot, Playbook, Run
from app.queue import claim_next
from app.reaper import reap_once
from app.vault import encrypt_to_vault_envelope, to_yaml_block
from tests.conftest import internal_client, start_worker
from tests.test_git_sources import _create, commit, git, local_git, make_repo  # noqa: F401
from tests.test_runs import (
    _create_credential,
    _create_vault_password,
    _login,
    _wait_for_completion,
)

ROLE_PLAY = "- hosts: all\n  connection: local\n  gather_facts: false\n  roles: [web]\n"
ROLE_TASKS = (
    "- name: render\n  ansible.builtin.template:\n    src: motd.j2\n"
    '    dest: "{{ marker_dir }}/motd"\n'
)


def _inventory(client: TestClient, marker_dir: Path, name: str = "git-inv") -> int:
    inventory = client.post("/api/inventories", json={"name": name}).json()
    response = client.post(
        f"/api/inventories/{inventory['id']}/hosts",
        json={"hostname": "localhost", "vars": {"marker_dir": str(marker_dir)}},
    )
    assert response.status_code == 201, response.text
    return inventory["id"]


def _synced(client: TestClient, repo: Path, **extra) -> dict[str, int]:
    source = _create(client, repo, **extra)
    assert git_sync.sync_source(source["id"]) == "ok"
    db = get_sessionmaker()()
    try:
        rows = db.scalars(select(Playbook).where(Playbook.source_id == source["id"])).all()
        return {p.repo_path: p.id for p in rows} | {"_source": source["id"]}
    finally:
        db.close()


def _trigger(client: TestClient, playbook_id: int, inventory_id: int, **extra) -> dict:
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name=f"c{playbook_id}{len(extra)}"),
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _fixture_repo(tmp_path: Path) -> Path:
    return make_repo(
        tmp_path / "repo",
        {
            "site.yml": ROLE_PLAY,
            "roles/web/tasks/main.yml": ROLE_TASKS,
            "roles/web/templates/motd.j2": "Hello {{ greeting }} from the repo\n",
            "group_vars/all.yml": "greeting: group_vars\n",
            "playbooks/include.yml": (
                "- hosts: all\n  connection: local\n  gather_facts: false\n  tasks:\n"
                "    - ansible.builtin.include_tasks: ../tasks/write.yml\n"
            ),
            "tasks/write.yml": (
                "- ansible.builtin.copy:\n    content: included\n"
                '    dest: "{{ marker_dir }}/included"\n'
            ),
        },
    )


@pytest.fixture
def admin(client: TestClient, local_git) -> TestClient:  # noqa: F811
    _login(client)
    return client


def test_a_git_run_executes_in_its_repository(admin, tmp_path) -> None:
    repo = _fixture_repo(tmp_path)
    ids = _synced(admin, repo, web_url="https://gitea.example.com/org/fixture")
    head = git(repo, "rev-parse", "HEAD").strip()
    inventory_id = _inventory(admin, tmp_path)

    run = _trigger(admin, ids["site.yml"], inventory_id)
    assert (run["git_commit"], run["playbook_path"], run["git_source_name"]) == (
        head,
        "site.yml",
        "repo",
    )
    assert run["commit_url"] == f"https://gitea.example.com/org/fixture/commit/{head}"
    done = _wait_for_completion(admin, run["id"], timeout=60)
    assert done["status"] == "success", done
    # The role's template, rendered with the repository's group_vars.
    assert (tmp_path / "motd").read_text() == "Hello group_vars from the repo\n"

    included = _wait_for_completion(
        admin, _trigger(admin, ids["playbooks/include.yml"], inventory_id)["id"], 60
    )
    assert included["status"] == "success", included
    assert (tmp_path / "included").read_text() == "included"


def test_the_repositorys_ansible_cfg_roles_path_works(admin, tmp_path) -> None:
    repo = make_repo(
        tmp_path / "repo",
        {
            "ansible.cfg": "[defaults]\nroles_path = ./my_roles:/etc/outside\n",
            "site.yml": ROLE_PLAY,
            "my_roles/web/tasks/main.yml": ROLE_TASKS,
            "my_roles/web/templates/motd.j2": "from my_roles\n",
        },
    )
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))
    assert _wait_for_completion(admin, run["id"], 60)["status"] == "success"
    assert (tmp_path / "motd").read_text() == "from my_roles\n"


@pytest.mark.no_worker
def test_a_queued_run_keeps_its_commit_when_the_branch_moves(admin, tmp_path) -> None:
    repo = _fixture_repo(tmp_path)
    ids = _synced(admin, repo)
    first = git(repo, "rev-parse", "HEAD").strip()
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))

    commit(repo, {"roles/web/templates/motd.j2": "the second commit\n"})
    git(repo, "commit", "-q", "--amend", "-m", "rewritten")  # a force-push, in effect
    assert git_sync.sync_source(ids["_source"]) == "ok"
    db = get_sessionmaker()()
    db.execute(update(GitSnapshot).values(superseded_at=GitSnapshot.created_at - os_hour()))
    db.commit()
    assert git_sync.prune_snapshots(db) == 0  # the queued run pins its snapshot
    db.close()

    worker = start_worker(tmp_path / "galaxy")
    try:
        done = _wait_for_completion(admin, run["id"], timeout=60)
    finally:
        worker.stop()
    assert done["status"] == "success" and done["git_commit"] == first
    assert (tmp_path / "motd").read_text() == "Hello group_vars from the repo\n"


def os_hour():
    from datetime import timedelta

    return timedelta(hours=1)


def test_vaulted_repository_vars_never_reach_the_output(admin, tmp_path) -> None:
    password = "repo-vault-password-7e2c"
    vault_id = _create_vault_password(admin, name="repo-vault", password=password)
    inline = to_yaml_block(encrypt_to_vault_envelope("inline-secret-91aa", password), "inline")
    whole = encrypt_to_vault_envelope("whole_file: whole-file-secret-55bd\n", password)
    repo = make_repo(
        tmp_path / "repo",
        {
            "site.yml": (
                "- hosts: all\n  connection: local\n  gather_facts: false\n  tasks:\n"
                "    - ansible.builtin.debug:\n"
                '        msg: "{{ inline }} {{ whole_file }} {{ db_password }}"\n'
            ),
            "group_vars/all/inline.yml": inline + "\n",
            "group_vars/all/vault.yml": whole,
            "group_vars/all/plain.yml": "db_password: plain-secret-3c4d\n",
        },
    )
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path), vault_password_id=vault_id)
    done = _wait_for_completion(admin, run["id"], 60)
    assert done["status"] == "success", done
    log = (tmp_path / "runs" / f"{run['id']}.jsonl").read_text()
    assert "REDACTED" in log
    for secret in ("inline-secret-91aa", "whole-file-secret-55bd", "plain-secret-3c4d", password):
        assert secret not in log, secret


def test_a_repositorys_yaml_result_format_cannot_fold_a_secret_past_the_scrubber(
    admin, tmp_path
) -> None:
    # YAML output folds a long value across lines, where the exact match can't find it.
    words = [f"fold{i:02d}x{i * 7919 % 10007:05d}" for i in range(24)]
    secret = " ".join(words)
    repo = make_repo(
        tmp_path / "repo",
        {
            "ansible.cfg": "[defaults]\ncallback_result_format = yaml\n",
            "site.yml": (
                "- hosts: all\n  connection: local\n  gather_facts: false\n  tasks:\n"
                '    - ansible.builtin.debug:\n        msg: "{{ db_password }}"\n'
            ),
            "group_vars/all.yml": f"db_password: {secret}\n",
        },
    )
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))
    assert _wait_for_completion(admin, run["id"], 60)["status"] == "success"
    log = (tmp_path / "runs" / f"{run['id']}.jsonl").read_text()
    assert "REDACTED" in log
    for word in words:
        assert word not in log, word


Member = tuple[tarfile.TarInfo, bytes]


def _tampered_tar(snapshot_id: int, members: list[Member]) -> None:
    """Replaces a snapshot's tar (and its recorded size and hash) with a crafted one."""
    raw = _tar(members).getvalue()
    db = get_sessionmaker()()
    snapshot = db.get(GitSnapshot, snapshot_id)
    git_sync.snapshot_path(snapshot).write_bytes(raw)
    snapshot.size_bytes, snapshot.sha256 = len(raw), hashlib.sha256(raw).hexdigest()
    db.commit()
    db.close()


def _file(name: str, data: bytes = b"x") -> Member:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def _link(name: str, target: str, kind=tarfile.SYMTYPE) -> Member:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info, b""


@pytest.mark.no_worker
def test_a_hostile_snapshot_is_refused_by_the_run_process(admin, tmp_path) -> None:
    """Defense in depth: even a tar that got past sync can't write outside the run."""
    repo = make_repo(tmp_path / "repo", {"site.yml": ROLE_PLAY})
    ids = _synced(admin, repo)
    inventory_id = _inventory(admin, tmp_path)
    escape = tmp_path / "escaped"
    run = _trigger(admin, ids["site.yml"], inventory_id)
    db = get_sessionmaker()()
    snapshot_id = db.get(Run, run["id"]).git_snapshot_id
    db.close()
    _tampered_tar(
        snapshot_id,
        [_file("site.yml", ROLE_PLAY.encode()), _file(f"../../../../../{escape}", b"pwned")],
    )
    worker = start_worker(tmp_path / "galaxy")
    try:
        done = _wait_for_completion(admin, run["id"], timeout=60)
    finally:
        worker.stop()
    assert done["status"] == "failed"
    assert done["status_reason"].startswith("not run:"), done["status_reason"]
    assert not escape.exists()


@pytest.mark.no_worker
def test_a_snapshot_that_doesnt_match_its_job_is_not_run(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": ROLE_PLAY})
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))
    db = get_sessionmaker()()
    snapshot = db.get(GitSnapshot, db.get(Run, run["id"]).git_snapshot_id)
    path = git_sync.snapshot_path(snapshot)
    db.close()
    data = bytearray(path.read_bytes())
    data[600] ^= 0xFF  # same size, other content
    path.write_bytes(bytes(data))
    worker = start_worker(tmp_path / "galaxy")
    try:
        done = _wait_for_completion(admin, run["id"], timeout=60)
    finally:
        worker.stop()
    assert (done["status"], done["status_reason"]) == ("failed", "could not fetch the repository")


@pytest.mark.no_worker
def test_a_queued_run_whose_source_is_gone_fails_with_a_reason(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": ROLE_PLAY})
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))
    db = get_sessionmaker()()
    db.execute(update(Run).where(Run.id == run["id"]).values(git_snapshot_id=None))
    db.commit()
    db.close()
    reap_once()
    done = admin.get(f"/api/runs/{run['id']}").json()
    assert done["status"] == "failed" and "git source" in done["status_reason"]


@pytest.mark.no_worker
def test_the_snapshot_endpoint_needs_the_runs_claim(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": ROLE_PLAY})
    ids = _synced(admin, repo)
    run = _trigger(admin, ids["site.yml"], _inventory(admin, tmp_path))
    db = get_sessionmaker()()
    claim = claim_next(db, "test-worker")
    db.close()
    assert claim is not None and claim.run_id == run["id"]
    internal = internal_client()
    path = f"/internal/runs/{run['id']}/snapshot"
    assert internal.post(path, headers={"X-Claim-Token": "wrong"}).status_code == 410
    response = internal.post(path, headers={"X-Claim-Token": claim.claim_token})
    assert response.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(response.content)) as tar:
        assert "site.yml" in tar.getnames()


def test_runs_of_missing_or_unsynced_playbooks_are_refused(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": ROLE_PLAY, "old.yml": ROLE_PLAY})
    ids = _synced(admin, repo)
    commit(repo, {"old.yml": None})
    git_sync.sync_source(ids["_source"])
    inventory_id = _inventory(admin, tmp_path)
    credential_id = _create_credential(admin, name="c-missing")
    response = admin.post(
        "/api/runs",
        json={
            "playbook_id": ids["old.yml"],
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    assert response.status_code == 409 and "no longer" in response.json()["detail"]


# ---------------------------------------------------------------- unpacking, unit level


def _tar(members: list[Member]) -> io.BytesIO:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data else None)
    buffer.seek(0)
    return buffer


@pytest.mark.parametrize(
    "member",
    [
        _file("../outside", b"x"),
        _link("abs", "/etc/passwd"),
        _link("rel", "../../etc/passwd"),
        _link("hard", "/etc/passwd", tarfile.LNKTYPE),
    ],
    ids=["dotdot", "abs-symlink", "escaping-symlink", "hardlink"],
)
def test_unpacking_refuses_anything_outside(tmp_path, member) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(tarfile.FilterError):
        run_worker.unpack_project(_tar([member]), project)
    assert not (tmp_path / "outside").exists()


def test_an_absolute_name_lands_inside_the_project(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_worker.unpack_project(_tar([_file(f"{tmp_path}/abs-target", b"x")]), project)
    assert not (tmp_path / "abs-target").exists()
    assert (project / str(tmp_path).lstrip("/") / "abs-target").read_bytes() == b"x"


def test_unpacking_refuses_devices_and_strips_setuid(tmp_path) -> None:
    device = tarfile.TarInfo("dev")
    device.type = tarfile.CHRTYPE
    with pytest.raises(tarfile.FilterError):
        run_worker.unpack_project(_tar([(device, b"")]), tmp_path / "a")
    setuid = _file("tool", b"#!/bin/sh\n")
    setuid[0].mode = 0o4755
    (tmp_path / "b").mkdir()
    run_worker.unpack_project(_tar([setuid]), tmp_path / "b")
    assert not os.stat(tmp_path / "b" / "tool").st_mode & 0o4000


def test_unpacking_limits_entries(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(run_worker, "MAX_PROJECT_ENTRIES", 2)
    (tmp_path / "p").mkdir()
    with pytest.raises(RuntimeError, match="too large"):
        run_worker.unpack_project(_tar([_file(f"f{i}") for i in range(3)]), tmp_path / "p")


def test_the_playbook_must_be_a_file_inside_the_project(tmp_path) -> None:
    project = tmp_path / "project"
    (project / "sub").mkdir(parents=True)
    (project / "site.yml").write_text("x")
    os.symlink("/etc/hosts", project / "outside.yml")
    os.symlink("site.yml", project / "alias.yml")
    assert run_worker.project_playbook(project, "site.yml") == "site.yml"
    assert run_worker.project_playbook(project, "alias.yml") == "alias.yml"
    for bad in ("../site.yml", "/etc/hosts", "outside.yml", "missing.yml", "sub", ""):
        with pytest.raises(RuntimeError):
            run_worker.project_playbook(project, bad)


def test_search_paths_put_the_repository_first(tmp_path, monkeypatch) -> None:
    project = tmp_path / "project"
    (project / "extra").mkdir(parents=True)
    (project / "ansible.cfg").write_text(
        "[defaults]\nroles_path = ./extra:/etc/elsewhere:../escape:~/home\n"
    )
    monkeypatch.setenv("ANSIBLE_ROLES_PATH", "/galaxy/roles")
    value = run_worker._search_path(project, "ANSIBLE_ROLES_PATH", ("roles_path",), "roles")
    real = os.path.realpath(project)
    assert value.split(os.pathsep) == [
        str(project / "roles"),
        f"{real}/extra",
        "/galaxy/roles",
    ]
