import json

import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app
from app.permissions import ROLE_PERMISSIONS, Permission, Role
from tests.conftest import make_user_client

ALL = {"viewer", "operator", "admin"}
OPERATOR_UP = {"operator", "admin"}
ADMIN = {"admin"}

# (method, path, roles allowed). Denied roles must get 403; allowed roles must
# NOT get 403 (they may get 404/422 for the dummy ids/bodies used here).
MATRIX = [
    ("GET", "/api/playbooks", ALL),
    ("POST", "/api/playbooks", OPERATOR_UP),
    ("PUT", "/api/playbooks/999", OPERATOR_UP),
    ("DELETE", "/api/playbooks/999", OPERATOR_UP),
    ("GET", "/api/inventories", ALL),
    ("POST", "/api/inventories", OPERATOR_UP),
    ("DELETE", "/api/inventories/999", OPERATOR_UP),
    ("POST", "/api/inventories/999/hosts", OPERATOR_UP),
    ("GET", "/api/credentials", OPERATOR_UP),
    ("POST", "/api/credentials", ADMIN),
    ("DELETE", "/api/credentials/999", ADMIN),
    ("GET", "/api/vault-passwords", OPERATOR_UP),
    ("POST", "/api/vault-passwords", ADMIN),
    ("DELETE", "/api/vault-passwords/999", ADMIN),
    ("POST", "/api/vault/encrypt", OPERATOR_UP),
    ("POST", "/api/vault/decrypt", ADMIN),
    ("GET", "/api/galaxy/requirements", ALL),
    ("GET", "/api/galaxy/installed", ALL),
    ("GET", "/api/galaxy/installs", ALL),
    ("PUT", "/api/galaxy/requirements", ADMIN),
    ("POST", "/api/galaxy/installs", ADMIN),
    ("GET", "/api/runs", ALL),
    ("GET", "/api/runs/999", ALL),
    ("POST", "/api/runs", OPERATOR_UP),
    ("GET", "/api/users", ADMIN),
    ("POST", "/api/users", ADMIN),
    ("PATCH", "/api/users/999", ADMIN),
    ("DELETE", "/api/users/999", ADMIN),
    ("GET", "/api/audit", ADMIN),
    ("GET", "/api/auth/me", ALL),
]


def _clients(client: TestClient) -> dict[str, TestClient]:
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return {
        "admin": client,
        "operator": make_user_client("operator1", "operator"),
        "viewer": make_user_client("viewer1", "viewer"),
    }


def _walk(dependant):
    yield dependant
    for sub in dependant.dependencies:
        yield from _walk(sub)


PUBLIC = {("/api/health", "GET"), ("/api/auth/login", "POST"), ("/api/auth/logout", "POST")}


def test_every_route_carries_a_permission_guard_or_is_explicitly_public() -> None:
    unguarded = []
    for route in app.routes:
        if isinstance(route, APIWebSocketRoute):
            continue  # guarded manually; covered by the websocket tests below
        if not isinstance(route, APIRoute):
            continue  # docs/openapi
        guarded = any(
            getattr(d.call, "_is_permission_guard", False) for d in _walk(route.dependant)
        )
        for method in route.methods:
            if not guarded and (route.path, method) not in PUBLIC:
                unguarded.append((method, route.path))
    assert unguarded == []


def test_role_permission_map_is_monotonic() -> None:
    viewer = ROLE_PERMISSIONS[Role.VIEWER]
    operator = ROLE_PERMISSIONS[Role.OPERATOR]
    admin = ROLE_PERMISSIONS[Role.ADMIN]
    assert viewer < operator < admin
    assert admin == set(Permission)
    for restricted in (Permission.RUNS_BECOME, Permission.VAULT_DECRYPT, Permission.SECRETS_MANAGE):
        assert restricted not in operator


@pytest.mark.parametrize(("method", "path", "allowed"), MATRIX)
def test_permission_matrix(client: TestClient, method: str, path: str, allowed: set[str]) -> None:
    for role, role_client in _clients(client).items():
        response = role_client.request(method, path, json={})
        if role in allowed:
            assert response.status_code != 403, f"{role} wrongly denied {method} {path}"
        else:
            assert response.status_code == 403, f"{role} wrongly allowed {method} {path}"


def test_unauthenticated_requests_get_401_not_403(client: TestClient) -> None:
    for method, path, _ in MATRIX:
        assert client.request(method, path, json={}).status_code == 401, (method, path)


def test_become_run_is_admin_only_and_denial_is_audited(client: TestClient) -> None:
    clients = _clients(client)
    payload = {"playbook_id": 1, "inventory_id": 1, "credential_id": 1, "become": True}

    denied = clients["operator"].post("/api/runs", json=payload)
    assert denied.status_code == 403
    assert "become" in denied.json()["detail"]
    assert clients["admin"].post("/api/runs", json=payload).status_code == 404  # passes the gate

    events = clients["admin"].get("/api/audit", params={"action": "permission.denied"}).json()
    assert any(
        e["actor_username"] == "operator1" and e["detail"]["required"] == "runs:become"
        for e in events["items"]
    )


def test_me_reports_role_and_permissions(client: TestClient) -> None:
    clients = _clients(client)
    viewer = clients["viewer"].get("/api/auth/me").json()
    assert viewer["role"] == "viewer"
    assert viewer["permissions"] == ["content:read"]
    operator = clients["operator"].get("/api/auth/me").json()
    assert "runs:trigger" in operator["permissions"]
    assert "runs:become" not in operator["permissions"]
    assert "vault:decrypt" not in operator["permissions"]


def test_viewer_sees_hidden_extra_vars_but_operator_sees_values(
    client: TestClient, tmp_path
) -> None:
    from tests.test_runs import (
        EXTRA_VARS_PLAYBOOK,
        _create_credential,
        _create_inventory_with_host,
        _create_playbook,
        _wait_for_completion,
    )

    clients = _clients(client)
    admin = clients["admin"]
    playbook_id = _create_playbook(admin, EXTRA_VARS_PLAYBOOK, name="rbac-extra.yml")
    inventory_id, _ = _create_inventory_with_host(admin, str(tmp_path / "m.txt"))
    credential_id = _create_credential(admin)
    created = clients["operator"].post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "extra_vars": {"greeting": "visible-to-operators"},
        },
    )
    assert created.status_code == 201
    assert created.json()["extra_vars"] == {"greeting": "visible-to-operators"}
    run_id = created.json()["id"]
    _wait_for_completion(admin, run_id)

    for path in (f"/api/runs/{run_id}", "/api/runs"):
        assert "visible-to-operators" in clients["operator"].get(path).text
        assert "visible-to-operators" in admin.get(path).text
        viewer_text = clients["viewer"].get(path).text
        assert "visible-to-operators" not in viewer_text
        assert "[HIDDEN]" in viewer_text
    assert clients["viewer"].get(f"/api/runs/{run_id}").json()["extra_vars"] == {
        "greeting": "[HIDDEN]"
    }


def test_websocket_requires_auth_permission_and_valid_origin(client: TestClient) -> None:
    clients = _clients(client)
    with pytest.raises(WebSocketDisconnect):
        with TestClient(app).websocket_connect("/api/runs/1/ws"):
            pass
    with pytest.raises(WebSocketDisconnect):
        with clients["admin"].websocket_connect(
            "/api/runs/1/ws", headers={"origin": "http://evil.example"}
        ):
            pass

    admin = clients["admin"]
    admin.patch("/api/users/1", json={"is_active": True})
    # deactivated users lose websocket access too
    user_id = admin.get("/api/users").json()
    viewer_id = next(u["id"] for u in user_id if u["username"] == "viewer1")
    assert admin.patch(f"/api/users/{viewer_id}", json={"is_active": False}).status_code == 200
    with pytest.raises(WebSocketDisconnect):
        with clients["viewer"].websocket_connect("/api/runs/1/ws"):
            pass


# ---------- Origin check (CSRF)


def test_origin_check_on_state_changing_requests(admin_client: TestClient) -> None:
    body = {"name": "origin.yml", "content": "- hosts: all\n  tasks: []\n"}
    evil = admin_client.post("/api/playbooks", json=body, headers={"origin": "http://evil.example"})
    assert evil.status_code == 403
    assert evil.json()["detail"] == "Origin not allowed"

    allow_listed = admin_client.post(
        "/api/playbooks", json=body, headers={"origin": "http://localhost:5173"}
    )
    assert allow_listed.status_code == 201

    same_origin = admin_client.post(
        "/api/playbooks",
        json={**body, "name": "origin2.yml"},
        headers={"origin": "http://testserver"},  # TestClient's Host is "testserver"
    )
    assert same_origin.status_code == 201

    no_origin = admin_client.post("/api/playbooks", json={**body, "name": "origin3.yml"})
    assert no_origin.status_code == 201


def test_origin_check_does_not_apply_to_safe_methods(admin_client: TestClient) -> None:
    response = admin_client.get("/api/playbooks", headers={"origin": "http://evil.example"})
    assert response.status_code == 200


# ---------- Users API


def test_user_lifecycle_and_session_invalidation(admin_client: TestClient) -> None:
    created = admin_client.post(
        "/api/users", json={"username": "newbie", "password": "a-decent-long-password"}
    )
    assert created.status_code == 201
    body = created.json()
    assert body["role"] == "viewer" and body["is_active"] is True
    assert body["created_by"] == "admin"
    assert "password" not in json.dumps(body)

    newbie = TestClient(app)
    assert (
        newbie.post(
            "/api/auth/login", json={"username": "newbie", "password": "a-decent-long-password"}
        ).status_code
        == 200
    )
    assert newbie.get("/api/auth/me").json()["role"] == "viewer"
    user_id = body["id"]

    # role change kills the live session immediately
    assert admin_client.patch(f"/api/users/{user_id}", json={"role": "operator"}).status_code == 200
    assert newbie.get("/api/auth/me").status_code == 401

    # ...and the fresh login reflects the new role
    newbie.post(
        "/api/auth/login", json={"username": "newbie", "password": "a-decent-long-password"}
    )
    assert newbie.get("/api/auth/me").json()["role"] == "operator"

    # deactivation kills it and blocks login
    assert admin_client.patch(f"/api/users/{user_id}", json={"is_active": False}).status_code == 200
    assert newbie.get("/api/auth/me").status_code == 401
    blocked = newbie.post(
        "/api/auth/login", json={"username": "newbie", "password": "a-decent-long-password"}
    )
    assert blocked.status_code == 401

    # reactivation + admin password reset: old password stops working
    admin_client.patch(f"/api/users/{user_id}", json={"is_active": True})
    reset = admin_client.patch(f"/api/users/{user_id}", json={"password": "a-brand-new-password-9"})
    assert reset.status_code == 200
    old = newbie.post(
        "/api/auth/login", json={"username": "newbie", "password": "a-decent-long-password"}
    )
    assert old.status_code == 401
    new = newbie.post(
        "/api/auth/login", json={"username": "newbie", "password": "a-brand-new-password-9"}
    )
    assert new.status_code == 200

    assert admin_client.delete(f"/api/users/{user_id}").status_code == 204
    assert newbie.get("/api/auth/me").status_code == 401


def test_user_creation_validation(admin_client: TestClient) -> None:
    def create(**overrides):
        payload = {"username": "someone", "password": "a-decent-long-password", **overrides}
        return admin_client.post("/api/users", json=payload)

    assert create(password="short").status_code == 422
    assert create(username="ab").status_code == 422
    assert create(username="bad name!").status_code == 422
    assert create(role="superuser").status_code == 422
    assert create(username="same-as-password-x", password="same-as-password-x").status_code == 400
    assert create().status_code == 201
    assert create().status_code == 400  # duplicate


def test_admin_cannot_lock_themselves_out(admin_client: TestClient) -> None:
    me = next(u for u in admin_client.get("/api/users").json() if u["username"] == "admin")
    for payload in ({"role": "viewer"}, {"is_active": False}):
        assert admin_client.patch(f"/api/users/{me['id']}", json=payload).status_code == 400
    assert (
        admin_client.patch(f"/api/users/{me['id']}", json={"password": "x" * 14}).status_code == 400
    )
    assert admin_client.delete(f"/api/users/{me['id']}").status_code == 400
    assert admin_client.get("/api/auth/me").status_code == 200  # still in


def test_last_active_admin_protection(client: TestClient) -> None:
    from app.db import get_sessionmaker
    from app.models import User
    from app.routers.users import _is_last_active_admin

    _clients(client)
    db = get_sessionmaker()()
    try:
        admin = db.query(User).filter(User.username == "admin").one()
        assert _is_last_active_admin(db, admin) is True
        assert (
            _is_last_active_admin(db, db.query(User).filter(User.username == "viewer1").one())
            is False
        )
        db.add(User(username="admin2", password_hash="x", role="admin"))
        db.commit()
        assert _is_last_active_admin(db, admin) is False
    finally:
        db.close()


def test_demoting_another_admin_is_allowed(admin_client: TestClient) -> None:
    created = admin_client.post(
        "/api/users",
        json={"username": "admin-two", "password": "a-decent-long-password", "role": "admin"},
    ).json()
    demoted = admin_client.patch(f"/api/users/{created['id']}", json={"role": "viewer"})
    assert demoted.status_code == 200 and demoted.json()["role"] == "viewer"


def test_change_password_invalidates_other_sessions_but_keeps_current(client: TestClient) -> None:
    first = make_user_client("pw-user", "operator")
    second = TestClient(app)
    second.post(
        "/api/auth/login", json={"username": "pw-user", "password": "a-long-test-password-1"}
    )

    assert (
        first.post(
            "/api/auth/change-password",
            json={
                "current_password": "a-long-test-password-1",
                "new_password": "another-long-password-2",
            },
        ).status_code
        == 200
    )
    assert first.get("/api/auth/me").status_code == 200  # cookie was re-issued
    assert second.get("/api/auth/me").status_code == 401  # other session signed out


def test_change_password_enforces_minimum_length(admin_client: TestClient) -> None:
    response = admin_client.post(
        "/api/auth/change-password", json={"current_password": "admin", "new_password": "short-pw"}
    )
    assert response.status_code == 422


# ---------- Login hardening


def test_login_throttle_blocks_after_repeated_failures_and_is_per_username(
    client: TestClient,
) -> None:
    for _ in range(5):
        assert (
            client.post(
                "/api/auth/login", json={"username": "admin", "password": "wrong"}
            ).status_code
            == 401
        )
    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "300"

    make_user_client("other-user", "viewer")  # a different username is unaffected
    assert (
        client.post(
            "/api/auth/login", json={"username": "other-user", "password": "a-long-test-password-1"}
        ).status_code
        == 200
    )


def test_successful_login_resets_the_user_throttle(client: TestClient) -> None:
    for _ in range(4):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )
    for _ in range(4):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )


def test_ip_throttle_stops_password_spraying_across_usernames(client: TestClient) -> None:
    for i in range(20):
        client.post("/api/auth/login", json={"username": f"spray{i}", "password": "wrong"})
    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert blocked.status_code == 429


def test_unknown_user_and_wrong_password_are_indistinguishable(
    client: TestClient, monkeypatch
) -> None:
    import app.routers.auth as auth_router

    calls = []
    real = auth_router.verify_password
    monkeypatch.setattr(auth_router, "verify_password", lambda p, h: calls.append(h) or real(p, h))

    unknown = client.post("/api/auth/login", json={"username": "nobody", "password": "whatever"})
    wrong = client.post("/api/auth/login", json={"username": "admin", "password": "whatever"})

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert len(calls) == 2  # an argon2 verify happened even for the unknown user


def test_client_ip_only_trusts_x_real_ip_from_private_peers() -> None:
    from starlette.requests import Request

    from app.hardening import client_ip

    def request(peer: str, real_ip: str | None) -> Request:
        headers = [(b"x-real-ip", real_ip.encode())] if real_ip else []
        return Request(
            {
                "type": "http",
                "client": (peer, 1234),
                "headers": headers,
                "method": "GET",
                "path": "/",
            }
        )

    assert client_ip(request("172.18.0.3", "203.0.113.9")) == "203.0.113.9"
    assert client_ip(request("127.0.0.1", "203.0.113.9")) == "203.0.113.9"
    assert client_ip(request("8.8.8.8", "203.0.113.9")) == "8.8.8.8"  # spoof ignored
    assert client_ip(request("172.18.0.3", "not-an-ip")) == "172.18.0.3"
    assert client_ip(request("172.18.0.3", None)) == "172.18.0.3"
