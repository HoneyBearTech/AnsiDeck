import json
import sqlite3
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app import audit
from app.config import get_settings
from app.crypto import hash_password
from app.db import get_engine, get_sessionmaker, init_db
from app.models import AuditEvent
from tests.conftest import make_user_client
from tests.test_credentials import _generate_key_pem


def _events(admin: TestClient, **params) -> list[dict]:
    response = admin.get("/api/audit", params={"limit": 200, **params})
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _actions(admin: TestClient, **params) -> list[str]:
    return [e["action"] for e in _events(admin, **params)]


def test_login_success_failure_and_logout_are_recorded(client: TestClient) -> None:
    client.post("/api/auth/login", json={"username": "admin", "password": "wrong-planted-pw-123"})
    client.post("/api/auth/login", json={"username": "ghost-user", "password": "x"})
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})

    events = _events(client)
    logins = [e for e in events if e["action"] == "auth.login"]
    assert sorted(e["outcome"] for e in logins) == ["failure", "failure", "success", "success"]
    unknown = next(
        e
        for e in logins
        if e["detail"]
        and e["detail"]["reason"] == "bad credentials"
        and e["actor_username"] != "admin"
    )
    assert unknown["actor_username"] == "(unknown user)"  # attempted name is not stored
    assert "ghost-user" not in json.dumps(events)
    assert any(e["action"] == "auth.logout" and e["actor_username"] == "admin" for e in events)
    assert all(e["ip"] for e in logins)


def test_security_relevant_actions_are_recorded(admin_client: TestClient) -> None:
    key_pem = _generate_key_pem()
    cred = admin_client.post("/api/credentials", json={"name": "c1", "private_key": key_pem}).json()
    vp = admin_client.post(
        "/api/vault-passwords", json={"name": "v1", "password": "vault-pw-audit-test"}
    ).json()
    enc = admin_client.post(
        "/api/vault/encrypt",
        json={"vault_password_id": vp["id"], "plaintext": "planted-plaintext-777"},
    ).json()
    admin_client.post(
        "/api/vault/decrypt", json={"vault_password_id": vp["id"], "ciphertext": enc["vault_text"]}
    )
    admin_client.put(
        "/api/galaxy/requirements", json={"content": "collections:\n  - community.general\n"}
    )
    user = admin_client.post(
        "/api/users",
        json={"username": "audited", "password": "audit-user-password-1", "role": "operator"},
    ).json()
    admin_client.patch(f"/api/users/{user['id']}", json={"role": "viewer"})
    admin_client.delete(f"/api/users/{user['id']}")
    admin_client.delete(f"/api/credentials/{cred['id']}")
    admin_client.delete(f"/api/vault-passwords/{vp['id']}")

    actions = _actions(admin_client)
    for expected in (
        "credential.create",
        "credential.delete",
        "vault_password.create",
        "vault_password.delete",
        "vault.encrypt",
        "vault.decrypt",
        "galaxy.requirements_update",
        "user.create",
        "user.update",
        "user.delete",
    ):
        assert expected in actions, f"missing audit action {expected}"

    delete = next(e for e in _events(admin_client) if e["action"] == "credential.delete")
    assert (
        delete["target_name"] == "c1" and delete["actor_username"] == "admin"
    )  # snapshot survives
    update = next(e for e in _events(admin_client) if e["action"] == "user.update")
    assert update["detail"]["changed"] == ["role"]


def test_password_change_and_run_trigger_are_recorded(admin_client: TestClient, tmp_path) -> None:
    from tests.test_runs import (
        SUCCESS_PLAYBOOK,
        _create_credential,
        _create_inventory_with_host,
        _create_playbook,
        _wait_for_completion,
    )

    playbook_id = _create_playbook(admin_client, SUCCESS_PLAYBOOK, name="audit-run.yml")
    inventory_id, _ = _create_inventory_with_host(admin_client, str(tmp_path / "m.txt"))
    credential_id = _create_credential(admin_client)
    run = admin_client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "become": False,
        },
    ).json()
    _wait_for_completion(admin_client, run["id"])
    admin_client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "a-new-admin-password-1"},
    )

    events = _events(admin_client)
    trigger = next(e for e in events if e["action"] == "run.trigger")
    assert trigger["target_id"] == run["id"]
    assert trigger["detail"]["playbook"] == "audit-run.yml"
    assert trigger["detail"]["become"] is False
    assert "auth.password_change" in [e["action"] for e in events]


def test_audit_rows_never_contain_secrets(admin_client: TestClient) -> None:
    planted = {
        "wrong-password": "planted-wrong-password-abc",
        "key": "PLANTEDKEYMATERIALLINE0123456789",
        "vault-pw": "planted-vault-password-def",
        "plaintext": "planted-plaintext-ghi",
        "new-user-pw": "planted-new-user-password-jkl",
        "extra": "planted-extra-var-mno",
    }
    TestClient(admin_client.app).post(
        "/api/auth/login", json={"username": "admin", "password": planted["wrong-password"]}
    )
    admin_client.post("/api/credentials", json={"name": "k", "private_key": _generate_key_pem()})
    vp = admin_client.post(
        "/api/vault-passwords", json={"name": "v", "password": planted["vault-pw"]}
    ).json()
    enc = admin_client.post(
        "/api/vault/encrypt",
        json={"vault_password_id": vp["id"], "plaintext": planted["plaintext"]},
    ).json()
    admin_client.post(
        "/api/vault/decrypt", json={"vault_password_id": vp["id"], "ciphertext": enc["vault_text"]}
    )
    admin_client.post(
        "/api/users", json={"username": "secretless", "password": planted["new-user-pw"]}
    )
    admin_client.post(
        "/api/runs",
        json={
            "playbook_id": 999,
            "inventory_id": 1,
            "credential_id": 1,
            "extra_vars": {"a": planted["extra"]},
        },
    )

    dump = json.dumps(_events(admin_client)) + json.dumps(_all_rows())
    for label, secret in planted.items():
        assert secret not in dump, f"{label} leaked into the audit log"
    assert "PRIVATE KEY" not in dump and "ANSIBLE_VAULT" not in dump


def _all_rows() -> list[dict]:
    db = get_sessionmaker()()
    try:
        return [
            {c.name: str(getattr(e, c.name)) for c in AuditEvent.__table__.columns}
            for e in db.query(AuditEvent).all()
        ]
    finally:
        db.close()


def test_audit_api_filters_and_paging(admin_client: TestClient) -> None:
    operator = make_user_client("op-audit", "operator")
    operator.get("/api/users")  # denied -> permission.denied event
    admin_client.post(
        "/api/users", json={"username": "filter1", "password": "filter-user-password-1"}
    )

    denied = _events(admin_client, outcome="denied")
    assert denied and all(e["outcome"] == "denied" for e in denied)
    assert all(e["actor_username"] == "op-audit" for e in _events(admin_client, actor="op-audit"))
    assert all(e["action"].startswith("user.") for e in _events(admin_client, action="user."))

    page1 = admin_client.get("/api/audit", params={"limit": 2, "offset": 0}).json()
    page2 = admin_client.get("/api/audit", params={"limit": 2, "offset": 2}).json()
    assert len(page1["items"]) == 2 and page1["total"] >= 4
    assert {e["id"] for e in page1["items"]}.isdisjoint({e["id"] for e in page2["items"]})
    assert page1["items"][0]["id"] > page1["items"][1]["id"]  # newest first

    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert _events(admin_client, since=future) == []
    assert admin_client.get("/api/audit", params={"limit": 0}).status_code == 422
    assert admin_client.get("/api/audit", params={"limit": 500}).status_code == 422


def test_audit_endpoint_is_admin_only(client: TestClient) -> None:
    assert make_user_client("v-audit", "viewer").get("/api/audit").status_code == 403
    assert make_user_client("o-audit", "operator").get("/api/audit").status_code == 403


def test_failed_login_audit_writes_are_bounded_per_ip(client: TestClient) -> None:
    for i in range(30):
        client.post("/api/auth/login", json={"username": f"flood{i}", "password": "x"})
    client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )  # 429, not logged
    db = get_sessionmaker()()
    try:
        failures = db.query(AuditEvent).filter(AuditEvent.outcome == "failure").count()
    finally:
        db.close()
    assert failures == 20


def test_prune_removes_only_old_events(client: TestClient) -> None:
    db = get_sessionmaker()()
    try:
        old = datetime.now(UTC) - timedelta(days=400)
        db.add(AuditEvent(action="old.event", outcome="success", created_at=old))
        db.add(AuditEvent(action="new.event", outcome="success"))
        db.commit()
        assert audit.prune(db, 0) == 0  # 0 = keep forever
        assert audit.prune(db, 365) == 1
        remaining = {e.action for e in db.query(AuditEvent).all()}
        assert remaining == {"new.event"}
    finally:
        db.close()


def test_audit_failure_never_breaks_the_request(client: TestClient, monkeypatch) -> None:
    def boom(**_kwargs):
        raise RuntimeError("audit table exploded")

    monkeypatch.setattr(audit, "AuditEvent", boom)
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200


def test_upgrade_from_pre_rbac_database(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    try:
        con = sqlite3.connect(tmp_path / "ansideck.db")
        con.executescript(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(150) UNIQUE,"
            " password_hash VARCHAR(255), created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"
        )
        con.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("legacy", hash_password("legacy-password-123")),
        )
        con.commit()
        con.close()

        init_db()
        init_db()  # idempotent on a second boot

        con = sqlite3.connect(tmp_path / "ansideck.db")
        row = con.execute(
            "SELECT username, role, is_active, session_version, created_by FROM users"
        ).fetchall()
        con.close()
        assert row == [("legacy", "admin", 1, 0, None)]  # the sole legacy user stays an admin

        upgraded = TestClient(__import__("app.main", fromlist=["app"]).app)
        response = upgraded.post(
            "/api/auth/login", json={"username": "legacy", "password": "legacy-password-123"}
        )
        assert response.status_code == 200
        assert response.json()["role"] == "admin"
        assert upgraded.get("/api/users").status_code == 200
    finally:
        get_engine.cache_clear()
        get_sessionmaker.cache_clear()
        get_settings.cache_clear()


def test_pre_rbac_session_cookies_are_rejected(client: TestClient) -> None:
    from itsdangerous import URLSafeTimedSerializer

    old_token = URLSafeTimedSerializer(
        get_settings().auth_secret_key, salt="ansideck-session"
    ).dumps({"sub": "admin"})
    client.cookies.set("ansideck_session", old_token)
    assert client.get("/api/auth/me").status_code == 401


def test_production_refuses_insecure_defaults(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    from app.config import Settings

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("AUTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with pytest.raises(ValidationError, match="AUTH_SECRET_KEY, ADMIN_PASSWORD"):
        Settings(_env_file=None)

    monkeypatch.setenv("AUTH_SECRET_KEY", "a-real-secret-value")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    assert Settings(_env_file=None).environment == "production"

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("AUTH_SECRET_KEY")
    monkeypatch.delenv("ADMIN_PASSWORD")
    assert Settings(_env_file=None).auth_secret_key  # dev keeps the convenient defaults
