from fastapi.testclient import TestClient


def _login(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def test_vault_password_crud_requires_auth(client: TestClient) -> None:
    assert client.get("/api/vault-passwords").status_code == 401
    assert (
        client.post("/api/vault-passwords", json={"name": "x", "password": "x"}).status_code == 401
    )
    assert client.delete("/api/vault-passwords/1").status_code == 401


def test_create_list_delete_vault_password(client: TestClient) -> None:
    _login(client)

    create_response = client.post(
        "/api/vault-passwords",
        json={"name": "prod-vault", "description": "prod secrets", "password": "hunter2"},
    )
    assert create_response.status_code == 201
    body = create_response.json()
    assert set(body.keys()) == {"id", "name", "description", "project_id", "created_at"}
    vault_password_id = body["id"]

    list_response = client.get("/api/vault-passwords")
    assert list_response.status_code == 200
    assert [v["id"] for v in list_response.json()] == [vault_password_id]
    assert set(list_response.json()[0].keys()) == {
        "id",
        "name",
        "description",
        "project_id",
        "created_at",
    }

    assert client.delete(f"/api/vault-passwords/{vault_password_id}").status_code == 204
    assert client.get("/api/vault-passwords").json() == []


def test_delete_missing_vault_password_returns_404(client: TestClient) -> None:
    _login(client)
    assert client.delete("/api/vault-passwords/999").status_code == 404


def test_vault_password_response_never_contains_password(client: TestClient) -> None:
    _login(client)
    password = "correct-horse-battery-staple"

    create_response = client.post(
        "/api/vault-passwords", json={"name": "secret-vault", "password": password}
    )
    assert password not in create_response.text
    assert password not in client.get("/api/vault-passwords").text


def test_vault_password_is_stored_encrypted(client: TestClient) -> None:
    from app.db import get_sessionmaker
    from app.models import VaultPassword

    _login(client)
    password = "stored-encrypted-check"
    client.post("/api/vault-passwords", json={"name": "enc-check", "password": password})

    db = get_sessionmaker()()
    try:
        row = db.query(VaultPassword).filter_by(name="enc-check").one()
        assert password.encode() not in row.encrypted_password
    finally:
        db.close()


def test_duplicate_vault_password_name_rejected(client: TestClient) -> None:
    _login(client)
    first = client.post("/api/vault-passwords", json={"name": "dup", "password": "one"})
    assert first.status_code == 201

    second = client.post("/api/vault-passwords", json={"name": "dup", "password": "two"})
    assert second.status_code == 400


def test_empty_vault_password_rejected(client: TestClient) -> None:
    _login(client)
    response = client.post("/api/vault-passwords", json={"name": "empty", "password": ""})
    assert response.status_code == 422
