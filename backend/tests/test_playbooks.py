from pathlib import Path

from fastapi.testclient import TestClient

VALID_CONTENT = "- hosts: all\n  tasks:\n    - debug:\n        msg: hello\n"


def _login(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def test_playbooks_require_auth(client: TestClient) -> None:
    assert client.get("/api/playbooks").status_code == 401
    assert client.post("/api/playbooks", json={"name": "x", "content": "x"}).status_code == 401
    assert client.get("/api/playbooks/1").status_code == 401
    assert client.put("/api/playbooks/1", json={"name": "x"}).status_code == 401
    assert client.delete("/api/playbooks/1").status_code == 401


def test_create_list_get_playbook(client: TestClient) -> None:
    _login(client)

    create_response = client.post(
        "/api/playbooks", json={"name": "deploy.yml", "content": VALID_CONTENT}
    )
    assert create_response.status_code == 201
    playbook_id = create_response.json()["id"]

    list_response = client.get("/api/playbooks")
    assert list_response.status_code == 200
    assert [p["id"] for p in list_response.json()] == [playbook_id]

    get_response = client.get(f"/api/playbooks/{playbook_id}")
    assert get_response.status_code == 200
    assert get_response.json()["content"] == VALID_CONTENT
    assert get_response.json()["name"] == "deploy.yml"


def test_create_playbook_rejects_invalid_yaml(client: TestClient, tmp_path: Path) -> None:
    _login(client)

    response = client.post("/api/playbooks", json={"name": "bad.yml", "content": "key: [unclosed"})
    assert response.status_code == 400

    assert client.get("/api/playbooks").json() == []
    playbooks_dir = tmp_path / "playbooks"
    assert not playbooks_dir.exists() or not any(playbooks_dir.iterdir())


def test_update_playbook_content_and_name(client: TestClient) -> None:
    _login(client)
    playbook_id = client.post(
        "/api/playbooks", json={"name": "old.yml", "content": VALID_CONTENT}
    ).json()["id"]

    new_content = "- hosts: all\n  tasks: []\n"
    update_response = client.put(
        f"/api/playbooks/{playbook_id}", json={"name": "new.yml", "content": new_content}
    )
    assert update_response.status_code == 200
    assert update_response.json()["name"] == "new.yml"
    assert update_response.json()["content"] == new_content


def test_update_playbook_rejects_invalid_yaml(client: TestClient) -> None:
    _login(client)
    playbook_id = client.post(
        "/api/playbooks", json={"name": "old.yml", "content": VALID_CONTENT}
    ).json()["id"]

    response = client.put(f"/api/playbooks/{playbook_id}", json={"content": "key: [unclosed"})
    assert response.status_code == 400

    get_response = client.get(f"/api/playbooks/{playbook_id}")
    assert get_response.json()["content"] == VALID_CONTENT


def test_delete_playbook_removes_file(client: TestClient) -> None:
    _login(client)
    playbook_id = client.post(
        "/api/playbooks", json={"name": "temp.yml", "content": VALID_CONTENT}
    ).json()["id"]

    delete_response = client.delete(f"/api/playbooks/{playbook_id}")
    assert delete_response.status_code == 204

    assert client.get(f"/api/playbooks/{playbook_id}").status_code == 404


def test_playbook_storage_is_id_keyed_not_name_derived(client: TestClient, tmp_path: Path) -> None:
    _login(client)

    response = client.post(
        "/api/playbooks",
        json={"name": "../../../etc/passwd", "content": VALID_CONTENT},
    )
    assert response.status_code == 201
    playbook_id = response.json()["id"]
    assert isinstance(playbook_id, int)

    get_response = client.get(f"/api/playbooks/{playbook_id}")
    assert get_response.status_code == 200
    assert get_response.json()["content"] == VALID_CONTENT

    playbooks_dir = tmp_path / "playbooks"
    files = list(playbooks_dir.glob("*"))
    assert files == [playbooks_dir / f"{playbook_id}.yml"]
