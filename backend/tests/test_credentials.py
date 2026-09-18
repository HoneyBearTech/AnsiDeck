from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient


def _login(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def _generate_key_pem(passphrase: bytes | None = None) -> str:
    private_key = ed25519.Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return pem.decode()


def test_credential_crud_requires_auth(client: TestClient) -> None:
    assert client.get("/api/credentials").status_code == 401
    assert (
        client.post("/api/credentials", json={"name": "x", "private_key": "x"}).status_code == 401
    )
    assert client.delete("/api/credentials/1").status_code == 401


def test_create_list_delete_credential(client: TestClient) -> None:
    _login(client)
    key_pem = _generate_key_pem()

    create_response = client.post(
        "/api/credentials",
        json={"name": "homelab-key", "description": "test key", "private_key": key_pem},
    )
    assert create_response.status_code == 201
    body = create_response.json()
    assert set(body.keys()) == {"id", "name", "description", "created_at"}
    credential_id = body["id"]

    list_response = client.get("/api/credentials")
    assert list_response.status_code == 200
    assert [c["id"] for c in list_response.json()] == [credential_id]
    assert set(list_response.json()[0].keys()) == {"id", "name", "description", "created_at"}

    delete_response = client.delete(f"/api/credentials/{credential_id}")
    assert delete_response.status_code == 204
    assert client.get("/api/credentials").json() == []


def test_create_credential_rejects_passphrase_protected_key(client: TestClient) -> None:
    _login(client)
    key_pem = _generate_key_pem(passphrase=b"supersecret")

    response = client.post(
        "/api/credentials", json={"name": "protected-key", "private_key": key_pem}
    )
    assert response.status_code == 400
    assert "passphrase" in response.json()["detail"].lower()


def test_create_credential_rejects_garbage_input(client: TestClient) -> None:
    _login(client)
    response = client.post("/api/credentials", json={"name": "garbage", "private_key": "not a key"})
    assert response.status_code == 400


def test_credential_response_never_contains_key_material(client: TestClient) -> None:
    _login(client)
    key_pem = _generate_key_pem()

    create_response = client.post(
        "/api/credentials", json={"name": "secret-key", "private_key": key_pem}
    )
    assert key_pem not in create_response.text

    list_response = client.get("/api/credentials")
    assert key_pem not in list_response.text


def test_duplicate_credential_name_rejected(client: TestClient) -> None:
    _login(client)
    key_pem_1 = _generate_key_pem()
    key_pem_2 = _generate_key_pem()

    first = client.post("/api/credentials", json={"name": "dup", "private_key": key_pem_1})
    assert first.status_code == 201

    second = client.post("/api/credentials", json={"name": "dup", "private_key": key_pem_2})
    assert second.status_code == 400
