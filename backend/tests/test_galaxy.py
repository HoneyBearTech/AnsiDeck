import subprocess
import tarfile
import textwrap
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import get_sessionmaker
from app.galaxy import (
    RequirementsError,
    _galaxy_binary,
    _install_commands,
    _install_env,
    validate_requirements,
)
from app.models import GalaxyInstall
from tests.test_runs import (
    PAUSE_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _wait_for_completion,
)

MODULE_SOURCE = """\
#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(argument_spec={"msg": {"type": "str", "default": "hi"}})
    module.exit_json(changed=False, greeting="collection says " + module.params["msg"])


if __name__ == "__main__":
    main()
"""

USES_GALAXY_CONTENT_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  vars:
    role_marker: "{{ marker_path }}.role"
  roles:
    - demorole
  tasks:
    - name: call installed collection module
      acme.demo.hello:
        msg: hi
      register: hello
    - name: write its result
      ansible.builtin.copy:
        content: "{{ hello.greeting }}"
        dest: "{{ marker_path }}"
"""


def _login(client: TestClient) -> None:
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )


def _wait_for_install(client: TestClient, install_id: int, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        install = client.get(f"/api/galaxy/installs/{install_id}").json()
        if install["status"] in ("success", "failed"):
            return install
        time.sleep(0.3)
    raise AssertionError(f"install {install_id} did not finish within {timeout}s")


@pytest.fixture
def local_sources(client: TestClient, tmp_path: Path, monkeypatch) -> dict[str, Path]:
    """Real collection + role tarballs, and permission to install from local paths
    (offline; never enabled outside tests)."""
    monkeypatch.setenv("GALAXY_ALLOW_LOCAL_SOURCES", "true")
    get_settings.cache_clear()

    src = tmp_path / "galaxy-src"
    collection = src / "acme_demo"
    (collection / "plugins" / "modules").mkdir(parents=True)
    (collection / "galaxy.yml").write_text(
        "namespace: acme\nname: demo\nversion: 1.0.0\nreadme: README.md\nauthors: [tester]\n"
    )
    (collection / "README.md").write_text("demo\n")
    (collection / "plugins" / "modules" / "hello.py").write_text(MODULE_SOURCE)

    role = src / "demorole"
    (role / "tasks").mkdir(parents=True)
    (role / "meta").mkdir()
    (role / "tasks" / "main.yml").write_text(
        textwrap.dedent(
            """\
            - name: write role marker
              ansible.builtin.copy:
                content: "from-role"
                dest: "{{ role_marker }}"
            """
        )
    )
    (role / "meta" / "main.yml").write_text(
        "galaxy_info:\n  author: t\n  description: d\n  license: MIT\n"
        '  min_ansible_version: "2.9"\n  platforms: []\ndependencies: []\n'
    )

    out = tmp_path / "galaxy-out"
    out.mkdir()
    subprocess.run(
        [_galaxy_binary(), "collection", "build", str(collection), "--output-path", str(out)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
    )
    role_tarball = out / "demorole.tar.gz"
    with tarfile.open(role_tarball, "w:gz") as tar:
        tar.add(role, arcname=".")

    return {"collection": out / "acme-demo-1.0.0.tar.gz", "role": role_tarball}


def _requirements_for(sources: dict[str, Path]) -> str:
    return (
        f"collections:\n  - name: {sources['collection']}\n"
        f"roles:\n  - name: demorole\n    src: {sources['role']}\n"
    )


def test_galaxy_endpoints_require_auth(client: TestClient) -> None:
    assert client.get("/api/galaxy/requirements").status_code == 401
    assert client.put("/api/galaxy/requirements", json={"content": ""}).status_code == 401
    assert client.get("/api/galaxy/installed").status_code == 401
    assert client.get("/api/galaxy/installs").status_code == 401
    assert client.get("/api/galaxy/installs/1").status_code == 401
    assert client.post("/api/galaxy/installs", json={}).status_code == 401


@pytest.mark.parametrize(
    "text",
    [
        "collections:\n  - community.general\n",
        'collections:\n  - name: community.general\n    version: ">=8.0.0"\n',
        "collections:\n  - name: https://example.com/x.tar.gz\n    type: url\n",
        (
            "collections:\n  - name: https://github.com/org/repo.git\n"
            "    type: git\n    version: main\n"
        ),
        "roles:\n  - geerlingguy.docker\n",
        'roles:\n  - name: geerlingguy.docker\n    version: "7.0.0"\n',
        "roles:\n  - src: git+https://github.com/org/role.git\n    name: myrole\n    version: v1\n",
        "roles:\n  - https://github.com/org/role.git\n",
        "collections: []\nroles: []\n",
        "",
    ],
)
def test_validate_requirements_accepts(text: str) -> None:
    validate_requirements(text)


@pytest.mark.parametrize(
    "text",
    [
        "- community.general\n",
        "other: []\n",
        "collections: community.general\n",
        "collections:\n  - name: /etc/passwd\n    type: file\n",
        "collections:\n  - name: /srv/collections\n    type: dir\n",
        "collections:\n  - name: /srv/collections\n    type: subdirs\n",
        "collections:\n  - /srv/some.tar.gz\n",
        "collections:\n  - name: file:///srv/x.tar.gz\n    type: url\n",
        "collections:\n  - name: http://example.com/x.tar.gz\n    type: url\n",
        "collections:\n  - name: https://user:pw@example.com/x.tar.gz\n    type: url\n",
        "collections:\n  - name: community.general\n    source: http://insecure.example\n",
        "collections:\n  - name: community.general\n    signatures: [x]\n",
        'collections:\n  - name: community.general\n    version: "--evil"\n',
        "collections:\n  - name: community.general\n    version: 1.0\n",
        "roles:\n  - /etc/hostname\n",
        "roles:\n  - src: /srv/role\n    name: r\n",
        "roles:\n  - src: file:///srv/role.tar.gz\n",
        "roles:\n  - src: 'ext::sh -c id'\n    name: r\n",
        "roles:\n  - src: git@github.com:org/role.git\n",
        "roles:\n  - src: git+ssh://github.com/org/role.git\n",
        "roles:\n  - src: https://github.com/org/role.git\n    scm: hg\n",
        "roles:\n  - src: https://github.com/org/role.git\n    name: ../evil\n",
        "roles:\n  - include: other.yml\n",
        "roles:\n  - name: a.b\n    version: '-x'\n",
        "x: !!python/object/apply:os.system ['id']\n",
    ],
)
def test_validate_requirements_rejects(text: str) -> None:
    with pytest.raises(RequirementsError):
        validate_requirements(text)


def test_validate_requirements_rejects_oversize_and_too_many() -> None:
    with pytest.raises(RequirementsError):
        validate_requirements("collections:\n" + "  - a.b\n" * 101)
    with pytest.raises(RequirementsError):
        validate_requirements("# " + "x" * (65 * 1024))


def test_requirements_get_put_roundtrip_and_rejection(client: TestClient) -> None:
    _login(client)
    assert client.get("/api/galaxy/requirements").json() == {"content": ""}

    bad = client.put("/api/galaxy/requirements", json={"content": "collections:\n  - /etc\n"})
    assert bad.status_code == 400
    assert client.get("/api/galaxy/requirements").json() == {"content": ""}

    content = "collections:\n  - community.general\n"
    assert client.put("/api/galaxy/requirements", json={"content": content}).status_code == 200
    assert client.get("/api/galaxy/requirements").json() == {"content": content}


def test_install_with_empty_requirements_is_rejected(client: TestClient) -> None:
    _login(client)
    response = client.post("/api/galaxy/installs", json={})
    assert response.status_code == 400


def test_install_commands_upgrade_flags(client: TestClient, tmp_path: Path) -> None:
    reqs = {"collections": ["a.b"], "roles": ["a.b"]}
    normal = _install_commands(reqs, tmp_path / "r.yml", upgrade=False)
    upgrade = _install_commands(reqs, tmp_path / "r.yml", upgrade=True)

    assert [c[1] for c in normal] == ["collection", "role"]
    assert not any("--upgrade" in c or "--force" in c for c in normal)
    assert "--upgrade" in upgrade[0] and "--force" not in upgrade[0]
    assert "--force" in upgrade[1] and "--upgrade" not in upgrade[1]
    assert (
        _install_commands({"collections": [], "roles": ["a.b"]}, tmp_path / "r.yml", False)[0][1]
        == "role"
    )


def test_install_env_excludes_app_secrets(client: TestClient) -> None:
    env = _install_env()
    assert "CREDENTIAL_ENCRYPTION_KEY" not in env
    assert "AUTH_SECRET_KEY" not in env
    assert "ADMIN_PASSWORD" not in env
    assert env["ANSIBLE_COLLECTIONS_PATH"].endswith("galaxy/collections")
    assert env["ANSIBLE_ROLES_PATH"].endswith("galaxy/roles")


def test_install_then_run_uses_installed_collection_and_role(
    client: TestClient, tmp_path: Path, local_sources: dict[str, Path]
) -> None:
    _login(client)
    put = client.put("/api/galaxy/requirements", json={"content": _requirements_for(local_sources)})
    assert put.status_code == 200

    create = client.post("/api/galaxy/installs", json={})
    assert create.status_code == 201
    install = _wait_for_install(client, create.json()["id"])
    assert install["status"] == "success", install["log"]
    assert install["return_code"] == 0
    assert install["triggered_by"] == "admin"
    assert "acme.demo:1.0.0 was installed successfully" in install["log"]
    assert "demorole was installed successfully" in install["log"]
    assert install["requirements_snapshot"] == _requirements_for(local_sources)

    installed = client.get("/api/galaxy/installed").json()
    assert installed["collections"] == [{"name": "acme.demo", "version": "1.0.0"}]
    assert installed["roles"] == [{"name": "demorole", "version": None}]

    assert [i["id"] for i in client.get("/api/galaxy/installs").json()] == [install["id"]]

    marker = tmp_path / "marker.txt"
    playbook_id = _create_playbook(client, USES_GALAXY_CONTENT_PLAYBOOK, name="galaxy-use.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(marker))
    credential_id = _create_credential(client)
    run_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    assert run_response.status_code == 201
    run = _wait_for_completion(client, run_response.json()["id"])
    assert run["status"] == "success", run

    assert marker.read_text() == "collection says hi"
    assert Path(f"{marker}.role").read_text() == "from-role"


def test_install_failure_is_reported_cleanly(
    client: TestClient, tmp_path: Path, local_sources: dict[str, Path]
) -> None:
    _login(client)
    missing = tmp_path / "does-not-exist.tar.gz"
    content = f"collections:\n  - name: {missing}\n"
    assert client.put("/api/galaxy/requirements", json={"content": content}).status_code == 200

    create = client.post("/api/galaxy/installs", json={})
    install = _wait_for_install(client, create.json()["id"])

    assert install["status"] == "failed"
    assert install["return_code"] != 0
    assert client.get("/api/galaxy/installed").json()["collections"] == []


def test_install_blocked_while_run_is_active(client: TestClient, tmp_path: Path) -> None:
    _login(client)
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name="pause-galaxy.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "m.txt"))
    credential_id = _create_credential(client)
    client.put(
        "/api/galaxy/requirements", json={"content": "collections:\n  - community.general\n"}
    )

    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    assert run.status_code == 201

    blocked = client.post("/api/galaxy/installs", json={})
    assert blocked.status_code == 409
    assert str(run.json()["id"]) in blocked.json()["detail"]

    _wait_for_completion(client, run.json()["id"])


def test_run_and_second_install_blocked_while_install_is_active(
    client: TestClient, tmp_path: Path
) -> None:
    _login(client)
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name="pause-galaxy2.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "m.txt"))
    credential_id = _create_credential(client)
    client.put(
        "/api/galaxy/requirements", json={"content": "collections:\n  - community.general\n"}
    )

    db = get_sessionmaker()()
    active = GalaxyInstall(status="running", triggered_by="admin", requirements_snapshot="x")
    db.add(active)
    db.commit()
    active_id = active.id
    db.close()

    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    assert run.status_code == 409
    assert str(active_id) in run.json()["detail"]

    second = client.post("/api/galaxy/installs", json={})
    assert second.status_code == 409
    assert str(active_id) in second.json()["detail"]


def test_get_missing_install_returns_404(client: TestClient) -> None:
    _login(client)
    assert client.get("/api/galaxy/installs/999").status_code == 404
