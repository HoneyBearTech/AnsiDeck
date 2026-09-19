from fastapi.testclient import TestClient

VAULT_HEADER = "$ANSIBLE_VAULT;1.1;AES256"


def _login(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def _create_vault_password(
    client: TestClient, name: str = "test-vault", password: str = "vault-pass"
) -> int:
    response = client.post("/api/vault-passwords", json={"name": name, "password": password})
    assert response.status_code == 201
    return response.json()["id"]


def test_vault_endpoints_require_auth(client: TestClient) -> None:
    assert (
        client.post(
            "/api/vault/encrypt", json={"vault_password_id": 1, "plaintext": "x"}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/vault/decrypt", json={"vault_password_id": 1, "ciphertext": "x"}
        ).status_code
        == 401
    )


def test_encrypt_returns_envelope_and_yaml_block(client: TestClient) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)

    response = client.post(
        "/api/vault/encrypt",
        json={"vault_password_id": vault_password_id, "plaintext": "s3cret", "var_name": "db_pass"},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["vault_text"].startswith(VAULT_HEADER)
    assert "s3cret" not in body["vault_text"]

    yaml_lines = body["yaml_block"].splitlines()
    assert yaml_lines[0] == "db_pass: !vault |"
    assert yaml_lines[1].strip() == VAULT_HEADER
    assert all(line.startswith(" " * 10) for line in yaml_lines[1:])


def test_encrypt_without_var_name_omits_key(client: TestClient) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)

    response = client.post(
        "/api/vault/encrypt",
        json={"vault_password_id": vault_password_id, "plaintext": "s3cret"},
    )
    assert response.json()["yaml_block"].splitlines()[0] == "!vault |"


def test_encrypt_decrypt_round_trip_raw_envelope(client: TestClient) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)

    encrypted = client.post(
        "/api/vault/encrypt",
        json={"vault_password_id": vault_password_id, "plaintext": "multi\nline\nsecret"},
    ).json()

    decrypted = client.post(
        "/api/vault/decrypt",
        json={"vault_password_id": vault_password_id, "ciphertext": encrypted["vault_text"]},
    )
    assert decrypted.status_code == 200
    assert decrypted.json() == {"plaintext": "multi\nline\nsecret"}


def test_encrypt_decrypt_round_trip_yaml_block(client: TestClient) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)

    encrypted = client.post(
        "/api/vault/encrypt",
        json={
            "vault_password_id": vault_password_id,
            "plaintext": "block-form-secret",
            "var_name": "api_token",
        },
    ).json()

    decrypted = client.post(
        "/api/vault/decrypt",
        json={"vault_password_id": vault_password_id, "ciphertext": encrypted["yaml_block"]},
    )
    assert decrypted.status_code == 200
    assert decrypted.json() == {"plaintext": "block-form-secret"}


def test_decrypt_with_wrong_password_returns_400(client: TestClient) -> None:
    _login(client)
    right_id = _create_vault_password(client, name="right", password="right-password")
    wrong_id = _create_vault_password(client, name="wrong", password="wrong-password")

    encrypted = client.post(
        "/api/vault/encrypt", json={"vault_password_id": right_id, "plaintext": "x"}
    ).json()

    response = client.post(
        "/api/vault/decrypt",
        json={"vault_password_id": wrong_id, "ciphertext": encrypted["vault_text"]},
    )
    assert response.status_code == 400


def test_decrypt_garbage_returns_400(client: TestClient) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)

    response = client.post(
        "/api/vault/decrypt",
        json={"vault_password_id": vault_password_id, "ciphertext": "not vault data"},
    )
    assert response.status_code == 400


def test_encrypt_decrypt_missing_vault_password_returns_404(client: TestClient) -> None:
    _login(client)

    assert (
        client.post(
            "/api/vault/encrypt", json={"vault_password_id": 999, "plaintext": "x"}
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/vault/decrypt", json={"vault_password_id": 999, "ciphertext": "x"}
        ).status_code
        == 404
    )


def test_vault_responses_never_contain_stored_password(client: TestClient) -> None:
    _login(client)
    password = "do-not-leak-this-password"
    vault_password_id = _create_vault_password(client, password=password)

    encrypted = client.post(
        "/api/vault/encrypt", json={"vault_password_id": vault_password_id, "plaintext": "x"}
    )
    decrypted = client.post(
        "/api/vault/decrypt",
        json={
            "vault_password_id": vault_password_id,
            "ciphertext": encrypted.json()["vault_text"],
        },
    )
    assert password not in encrypted.text
    assert password not in decrypted.text
