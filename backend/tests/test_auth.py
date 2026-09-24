from fastapi.testclient import TestClient


def test_me_requires_auth(client: TestClient) -> None:
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_login_with_wrong_password_fails(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_login_then_me_then_logout(client: TestClient) -> None:
    login_response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login_response.status_code == 200
    assert login_response.json()["username"] == "admin"
    assert login_response.json()["role"] == "admin"

    me_response = client.get("/api/auth/me")
    assert me_response.status_code == 200
    assert me_response.json()["username"] == "admin"
    assert me_response.json()["role"] == "admin"
    assert "runs:become" in me_response.json()["permissions"]

    logout_response = client.post("/api/auth/logout")
    assert logout_response.status_code == 200

    me_after_logout = client.get("/api/auth/me")
    assert me_after_logout.status_code == 401


def test_change_password_requires_auth(client: TestClient) -> None:
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "newpassword123"},
    )
    assert response.status_code == 401


def test_change_password_wrong_current_password_fails(client: TestClient) -> None:
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "wrong", "new_password": "newpassword123"},
    )
    assert response.status_code == 401

    # old password still works
    relogin = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert relogin.status_code == 200


def test_change_password_then_relogin(client: TestClient) -> None:
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})

    change_response = client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "newpassword123"},
    )
    assert change_response.status_code == 200

    client.post("/api/auth/logout")

    old_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert old_login.status_code == 401

    new_login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "newpassword123"}
    )
    assert new_login.status_code == 200


def _change(client: TestClient, current: str, new: str = "newpassword123") -> int:
    return client.post(
        "/api/auth/change-password", json={"current_password": current, "new_password": new}
    ).status_code


def test_change_password_guesses_share_the_login_throttle(client: TestClient) -> None:
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})

    assert [_change(client, f"guess-{i}") for i in range(5)] == [401] * 5

    # Blocked even with the right password, here and at login, and nothing changed.
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "newpassword123"},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "300"
    relogin = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert relogin.status_code == 429


def test_change_password_success_resets_the_throttle(client: TestClient) -> None:
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})

    assert [_change(client, f"guess-{i}") for i in range(4)] == [401] * 4
    assert _change(client, "admin") == 200
    assert [_change(client, f"guess-{i}") for i in range(4)] == [401] * 4
