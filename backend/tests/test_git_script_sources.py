"""Inventory scripts from a git source (app.inventory_files.read_script_files): an executable
script with a "#!" line, run by the script plugin with its directory beside it and only its own
source's credential; its output scrubbed and never templated like any source's."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import git_sync
from app.config import get_settings
from app.inventory_files import InventoryFileError, read_script_files
from tests.test_git_file_sources import _snapshot
from tests.test_git_sources import _admin, _create, git, make_repo
from tests.test_inventory_sources import _env_credential, _wait_refresh

SCRIPT = """\
#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

if "--host" in sys.argv:
    print("{}")
    sys.exit()
site = (Path(__file__).parent / "site.ini").read_text().split("=", 1)[1].strip()
print(json.dumps({
    "_meta": {"hostvars": {
        "app1": {
            "site": site,
            "token": os.environ.get("APP_TOKEN", "none"),
            "sees_other": "OTHER_TOKEN" in os.environ,
            "note": "{{ 6 * 7 }}",
            "cwd": os.path.basename(os.getcwd()),
        },
    }},
    "apps": {"hosts": ["app1"]},
}))
"""
TOKEN = "app-script-token-sentinel"


@pytest.fixture
def admin(client: TestClient, monkeypatch) -> TestClient:
    monkeypatch.setenv("GIT_ALLOW_LOCAL_SOURCES", "true")
    get_settings.cache_clear()
    yield _admin(client)
    get_settings.cache_clear()


def _repo(tmp_path: Path, executable: bool = True, script: str = SCRIPT) -> Path:
    repo = make_repo(
        tmp_path / "repo",
        {"inventory/apps.py": script, "inventory/site.ini": "site = lab\n", "README.md": "x\n"},
    )
    if executable:
        git(repo, "update-index", "--chmod=+x", "inventory/apps.py")
        git(repo, "commit", "-q", "-m", "executable")
    return repo


def _synced(admin: TestClient, repo: Path) -> dict:
    source = _create(admin, repo)
    assert git_sync.sync_source(source["id"]) in ("ok", "unchanged")
    return source


@pytest.mark.no_worker
def test_a_script_is_a_file_in_the_commit(admin: TestClient, tmp_path: Path) -> None:
    """Its execute bit doesn't matter: it runs through the interpreter its #! line names."""
    source = _synced(admin, _repo(tmp_path, executable=False))
    snapshot = _snapshot(source["id"])
    assert read_script_files(snapshot, "inventory/apps.py").target == "inventory/apps.py"
    with pytest.raises(InventoryFileError, match="is not a file"):
        read_script_files(snapshot, "inventory")


@pytest.mark.no_worker
def test_a_script_comes_with_its_directory(admin: TestClient, tmp_path: Path) -> None:
    source = _synced(admin, _repo(tmp_path))
    found = read_script_files(_snapshot(source["id"]), "inventory/apps.py")
    assert [(f["name"], f["executable"]) for f in found.files] == [
        ("inventory/apps.py", True),
        ("inventory/site.ini", False),
    ]  # not README.md: outside its directory


@pytest.mark.no_worker
def test_a_script_without_a_shebang_is_refused(admin: TestClient, tmp_path: Path) -> None:
    source = _synced(admin, _repo(tmp_path, script="print('{}')\n"))
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    response = admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "apps",
            "kind": "git_script",
            "git_source_id": source["id"],
            "path": "inventory/apps.py",
        },
    )
    assert response.status_code == 400 and "#! line" in response.text
    file_credential = admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "f",
            "kind": "git_file",
            "git_source_id": source["id"],
            "path": "inventory/site.ini",
            "credential_id": 1,
        },
    )
    assert file_credential.status_code == 422  # an inventory file reads no credential


def test_a_script_runs_with_its_files_and_only_its_own_credential(
    admin: TestClient, tmp_path: Path
) -> None:
    """A real worker: the script reads the file beside it from its own directory, gets its own
    credential and not another source's, and its output is scrubbed and never templated."""
    source = _synced(admin, _repo(tmp_path))
    inventory_id = admin.post("/api/inventories", json={"name": "dyn"}).json()["id"]
    own = _env_credential(admin, {"APP_TOKEN": TOKEN}, name="app")
    other = _env_credential(admin, {"OTHER_TOKEN": "other-token-sentinel"}, name="other")
    gen = "plugin: ansible.builtin.generator\nhosts:\n  name: gen-{{ x }}\nlayers:\n  x: [a]\n"
    admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={"name": "gen", "config": gen, "credential_id": other},
    )
    created = admin.post(
        f"/api/inventories/{inventory_id}/sources",
        json={
            "name": "apps",
            "kind": "git_script",
            "git_source_id": source["id"],
            "path": "inventory/apps.py",
            "credential_id": own,
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["plugin"] == "script"
    refresh = _wait_refresh(admin, inventory_id)
    assert refresh["status"] == "success", refresh
    hosts = {
        h["name"]: h for h in admin.get(f"/api/inventories/{inventory_id}/hosts").json()["hosts"]
    }
    app1 = hosts["app1"]["vars"]
    assert app1["site"] == "lab" and app1["cwd"] == "inventory"
    assert app1["sees_other"] is False
    assert app1["note"] == "{{ 6 * 7 }}"
    assert TOKEN not in str(app1)  # the credential's value was redacted from the output
    snapshot = admin.get(f"/api/inventories/{inventory_id}/snapshot").json()
    assert any("redacted" in warning for warning in snapshot["warnings"])
    assert "apps" in {g["name"] for g in snapshot["groups"]}
