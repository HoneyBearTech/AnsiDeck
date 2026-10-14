"""Inventory files from a git source (app.inventory_files): a path in a synced repository, read
from its current commit with the group_vars/ and host_vars/ beside it, run by ansible-inventory
as YAML or INI only; filtered like every source; refreshed when the git source's commit changes
them; and a git source that inventory sources read from can't be deleted."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import git_sync
from app.config import get_settings
from app.db import get_sessionmaker
from app.inventory_files import InventoryFileError, check_path, read_inventory_files
from app.models import GitSnapshot, GitSource, InventoryRefresh, InventorySource, RunStatus
from tests.test_git_sources import _admin, _create, commit, make_repo
from tests.test_inventory_sources import _wait_refresh

INI = """\
[web]
web1 ansible_host=10.0.0.1 ansible_connection=local
web2

[db]
db1 role=primary
"""
FILES = {
    "inventory/hosts.ini": INI,
    "inventory/group_vars/web.yml": "tier: front\nansible_become: true\n",
    "inventory/host_vars/db1.yml": "backup: nightly\n",
    "group_vars/all.yml": "not_beside_the_file: true\n",
    "site.yml": "- hosts: all\n  tasks: []\n",
}


@pytest.fixture
def admin(client: TestClient, monkeypatch) -> TestClient:
    """An admin, with local (file://) git sources allowed for the test repositories."""
    monkeypatch.setenv("GIT_ALLOW_LOCAL_SOURCES", "true")
    get_settings.cache_clear()
    yield _admin(client)
    get_settings.cache_clear()


def _synced_repo(admin: TestClient, tmp_path: Path, files: dict | None = None) -> tuple[Path, dict]:
    repo = make_repo(tmp_path / "repo", files or FILES)
    source = _create(admin, repo)
    assert git_sync.sync_source(source["id"]) in ("ok", "unchanged")
    return repo, source


def _snapshot(git_source_id: int) -> GitSnapshot:
    db = get_sessionmaker()()
    try:
        source = db.get(GitSource, git_source_id)
        snapshot = db.get(GitSnapshot, source.current_snapshot_id)
        db.expunge(snapshot)
        return snapshot
    finally:
        db.close()


@pytest.mark.parametrize("path", ["", "/", "../x", "a/../b", "a//b", "./a", "a\0b", "x" * 1025])
def test_a_path_stays_inside_the_repository(path: str) -> None:
    with pytest.raises(InventoryFileError):
        check_path(path)


@pytest.mark.no_worker
def test_the_file_comes_with_the_vars_beside_it(admin: TestClient, tmp_path: Path) -> None:
    _repo, source = _synced_repo(admin, tmp_path)
    snapshot = _snapshot(source["id"])
    found = read_inventory_files(snapshot, "inventory/hosts.ini")
    assert [f["name"] for f in found.files] == [
        "inventory/group_vars/web.yml",
        "inventory/host_vars/db1.yml",
        "inventory/hosts.ini",
    ]
    assert found.target == "inventory/hosts.ini"
    directory = read_inventory_files(snapshot, "inventory/")
    assert directory.target == "inventory" and len(directory.files) == 3
    assert directory.digest != found.digest or directory.files == found.files
    with pytest.raises(InventoryFileError, match="is not in commit"):
        read_inventory_files(snapshot, "inventory/missing.ini")


@pytest.mark.no_worker
@pytest.mark.parametrize(
    "body",
    [
        {"kind": "git_file", "path": "inventory/hosts.ini"},  # no git source
        {"kind": "git_file", "git_source_id": 1},  # no path
        {"kind": "git_file", "git_source_id": 1, "path": "x", "config": "plugin: x"},
        {"kind": "git_file", "git_source_id": 1, "path": "x", "credential_id": 1},
        {"kind": "plugin", "config": "plugin: x", "path": "x"},
    ],
)
def test_a_sources_fields_are_those_of_its_kind(admin: TestClient, body: dict) -> None:
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    response = admin.post(f"/api/inventories/{inventory_id}/sources", json={"name": "s", **body})
    assert response.status_code == 422, response.text


@pytest.mark.no_worker
def test_the_path_must_be_in_the_git_sources_commit(admin: TestClient, tmp_path: Path) -> None:
    _repo, source = _synced_repo(admin, tmp_path)
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    url = f"/api/inventories/{inventory_id}/sources"
    missing = admin.post(
        url,
        json={"name": "s", "kind": "git_file", "git_source_id": source["id"], "path": "nope.ini"},
    )
    assert missing.status_code == 400 and "is not in commit" in missing.text
    elsewhere = admin.post(
        url, json={"name": "s", "kind": "git_file", "git_source_id": 999999, "path": "x"}
    )
    assert elsewhere.status_code == 400 and "git source of this project" in elsewhere.text
    ok = admin.post(
        url,
        json={
            "name": "s",
            "kind": "git_file",
            "git_source_id": source["id"],
            "path": "/inventory/hosts.ini",
        },
    )
    assert ok.status_code == 201, ok.text
    body = ok.json()
    assert (body["kind"], body["path"], body["git_source_name"], body["config"]) == (
        "git_file",
        "inventory/hosts.ini",
        "repo",
        None,
    )
    config = admin.patch(f"{url}/{body['id']}", json={"config": "plugin: x"})
    assert config.status_code == 400
    delete = admin.delete(f"/api/projects/1/git-sources/{source['id']}")
    assert delete.status_code == 409 and "'s' reads a file from this git source" in delete.text


def test_a_refresh_reads_the_file_as_an_inventory_and_filters_it(
    admin: TestClient, tmp_path: Path
) -> None:
    """A real worker: INI hosts and groups with the vars beside them; connection and become
    settings dropped as for any source; nothing from outside the file's directory."""
    _repo, source = _synced_repo(admin, tmp_path)
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    created = admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "file",
            "kind": "git_file",
            "git_source_id": source["id"],
            "path": "inventory/hosts.ini",
        },
    ).json()
    refresh = _wait_refresh(admin, inventory_id)
    assert refresh["status"] == "success", refresh
    hosts = {
        h["name"]: h for h in admin.get(f"/api/inventories/{inventory_id}/hosts").json()["hosts"]
    }
    assert set(hosts) == {"web1", "web2", "db1"}
    assert hosts["web1"]["vars"].get("ansible_host") == "10.0.0.1"
    assert "ansible_connection" not in hosts["web1"]["vars"]
    assert hosts["db1"]["vars"]["backup"] == "nightly"
    snapshot = admin.get(f"/api/inventories/{inventory_id}/snapshot").json()
    groups = {g["name"]: g for g in snapshot["groups"]}
    assert groups["web"]["vars"] == {"tier": "front"}  # ansible_become dropped
    assert any("ansible_become" in w for w in snapshot["warnings"])
    assert "not_beside_the_file" not in str(snapshot)
    out = {s["name"]: s for s in admin.get(f"/api/inventories/{inventory_id}/sources").json()}
    assert out["file"]["output_host_count"] == 3 and len(out["file"]["output_git_commit"]) == 40
    assert created["id"] == out["file"]["id"]


def test_a_plugin_config_in_a_git_file_isnt_loaded(admin: TestClient, tmp_path: Path) -> None:
    files = {"inv.yml": "plugin: ansible.builtin.generator\nhosts:\n  name: x\n"}
    _repo, source = _synced_repo(admin, tmp_path, files)
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={"name": "file", "kind": "git_file", "git_source_id": source["id"], "path": "inv.yml"},
    )
    refresh = _wait_refresh(admin, inventory_id)
    assert refresh["status"] == "failed" and refresh["error"].startswith("source 'file': ")


def _queued_scope(inventory_id: int) -> list[int] | str | None:
    db = get_sessionmaker()()
    try:
        row = db.scalars(
            select(InventoryRefresh).where(
                InventoryRefresh.inventory_id == inventory_id,
                InventoryRefresh.status == RunStatus.QUEUED.value,
            )
        ).first()
        return "none" if row is None else row.scope
    finally:
        db.close()


@pytest.mark.no_worker
def test_a_new_commit_refreshes_only_the_files_it_changed(
    admin: TestClient, tmp_path: Path
) -> None:
    repo, source = _synced_repo(admin, tmp_path)
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    created = admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "file",
            "kind": "git_file",
            "git_source_id": source["id"],
            "path": "inventory/hosts.ini",
        },
    ).json()
    db = get_sessionmaker()()
    db.query(InventoryRefresh).delete()
    db.commit()
    db.close()

    commit(repo, {"site.yml": "- hosts: all\n  tasks: []\n# changed\n"})
    assert git_sync.sync_source(source["id"]) == "ok"
    assert _queued_scope(inventory_id) == "none"  # not one of its files

    commit(repo, {"inventory/group_vars/web.yml": "tier: back\n"})
    assert git_sync.sync_source(source["id"]) == "ok"
    assert _queued_scope(inventory_id) == [created["id"]]
    db = get_sessionmaker()()
    assert db.scalar(select(InventoryRefresh.trigger)) == "git_sync"
    db.query(InventoryRefresh).delete()
    db.commit()
    db.close()

    commit(repo, {"inventory/hosts.ini": None})
    assert git_sync.sync_source(source["id"]) == "ok"
    assert _queued_scope(inventory_id) == [created["id"]]  # gone: it runs, and fails
    db = get_sessionmaker()()
    assert db.get(InventorySource, created["id"]).missing_at is not None
    db.close()


def test_a_file_gone_upstream_fails_its_source_which_keeps_its_hosts(
    admin: TestClient, tmp_path: Path
) -> None:
    repo, source = _synced_repo(admin, tmp_path)
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "file",
            "kind": "git_file",
            "git_source_id": source["id"],
            "path": "inventory/hosts.ini",
        },
    )
    assert _wait_refresh(admin, inventory_id)["status"] == "success"
    first_id = admin.get(f"/api/inventories/{inventory_id}/refreshes").json()[0]["id"]
    commit(repo, {"inventory/hosts.ini": None})
    git_sync.sync_source(source["id"])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        latest = admin.get(f"/api/inventories/{inventory_id}/refreshes").json()[0]
        if latest["id"] != first_id and latest["status"] not in ("queued", "running"):
            break
        time.sleep(0.2)
    assert latest["status"] == "failed" and "is not in commit" in latest["error"]
    assert admin.get(f"/api/inventories/{inventory_id}/targets").json()["hosts"] == 3
    out = admin.get(f"/api/inventories/{inventory_id}/sources").json()[0]
    assert out["missing_at"] is not None and "is not in commit" in out["last_error"]
