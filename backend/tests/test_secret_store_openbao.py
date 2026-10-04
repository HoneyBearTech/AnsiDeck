"""The secret store against a real OpenBao (or Vault) dev server: AppRole, a read-only policy
on AnsiDeck's prefix, per-project policies, runs using stored keys and vault passwords, and a
store outage. Skipped unless TEST_OPENBAO_ADDR and TEST_OPENBAO_ROOT_TOKEN are set (CI runs an
OpenBao service; locally: docker run -d -p 127.0.0.1:18200:8200 -e BAO_DEV_ROOT_TOKEN_ID=root
openbao/openbao)."""

import os
import uuid

import httpx
import pytest
from sqlalchemy import select, text

from app import secret_store
from app.config import get_settings
from app.db import Base, get_engine, get_sessionmaker
from app.main import _probe_secret_store
from app.models import NotificationAlert
from app.secret_store import SecretStoreError
from tests.test_runs import (
    _create_inventory_with_host,
    _create_playbook,
    _generate_key_pem,
    _login,
    _vault_var_playbook,
    _wait_for_completion,
)

ADDR = os.environ.get("TEST_OPENBAO_ADDR", "")
ROOT = os.environ.get("TEST_OPENBAO_ROOT_TOKEN", "")
pytestmark = pytest.mark.skipif(not (ADDR and ROOT), reason="no TEST_OPENBAO_ADDR / _ROOT_TOKEN")
PREFIX = "ansideck-test"


def _admin() -> httpx.Client:
    return httpx.Client(base_url=ADDR, headers={"X-Vault-Token": ROOT}, timeout=10)


def put_secret(project_id: int, path: str, data: dict) -> None:
    with _admin() as bao:
        response = bao.post(f"/v1/secret/data/{PREFIX}/{project_id}/{path}", json={"data": data})
        assert response.status_code == 200, response.text


@pytest.fixture(scope="module")
def approle() -> dict:
    """An AppRole that may read secret/data/ansideck-test/* and mint per-project child
    tokens (projects 1-3), like the README's setup."""
    with _admin() as bao:
        bao.post("/v1/sys/auth/approle", json={"type": "approle"})  # 400 once it exists
        policies = {
            "ansideck-test-base": (
                f'path "secret/data/{PREFIX}/*" {{ capabilities = ["read"] }}\n'
                'path "auth/token/create" { capabilities = ["update"] }\n'
            )
        }
        for project in (1, 2, 3):
            policies[f"ansideck-test-p{project}"] = (
                f'path "secret/data/{PREFIX}/{project}/*" {{ capabilities = ["read"] }}\n'
            )
        for name, rules in policies.items():
            assert (
                bao.put(f"/v1/sys/policies/acl/{name}", json={"policy": rules}).status_code == 204
            )
        role = bao.post(
            "/v1/auth/approle/role/ansideck-test",
            json={"token_policies": list(policies), "token_ttl": "10m", "token_max_ttl": "30m"},
        )
        assert role.status_code == 204, role.text
        role_id = bao.get("/v1/auth/approle/role/ansideck-test/role-id").json()["data"]["role_id"]
        secret_id = bao.post("/v1/auth/approle/role/ansideck-test/secret-id").json()["data"][
            "secret_id"
        ]
    return {"role_id": role_id, "secret_id": secret_id}


@pytest.fixture
def store(client, approle, monkeypatch, tmp_path):
    sid = tmp_path / "secret_id"
    sid.write_text(approle["secret_id"])
    for name, value in {
        "SECRETS_STORE_URL": ADDR,
        "SECRETS_STORE_AUTH": "approle",
        "SECRETS_STORE_ROLE_ID": approle["role_id"],
        "SECRETS_STORE_SECRET_ID_FILE": str(sid),
        "SECRETS_STORE_PATH_PREFIX": PREFIX,
    }.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    secret_store.reset()
    yield
    secret_store.reset()
    get_settings.cache_clear()


def test_a_real_read_through_approle(store) -> None:
    put_secret(1, "web/ssh", {"private_key": "k1", "other": "x"})
    value, version = secret_store.read_versioned(1, "web/ssh", "private_key")
    assert value == "k1" and version >= 1
    with pytest.raises(SecretStoreError) as missing:
        secret_store.read_secret(1, "web/nope", "private_key")
    assert missing.value.kind == "not_found"
    with pytest.raises(SecretStoreError) as key:
        secret_store.read_secret(1, "web/ssh", "absent")
    assert key.value.kind == "missing_key"


def test_the_store_policy_limits_ansideck_to_its_prefix(store, monkeypatch) -> None:
    with _admin() as bao:
        bao.post("/v1/secret/data/elsewhere/1/x", json={"data": {"k": "v"}})
    monkeypatch.setenv("SECRETS_STORE_PATH_PREFIX", "elsewhere")
    get_settings.cache_clear()
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(1, "x", "k")
    assert error.value.kind == "denied"


def test_per_project_child_tokens_let_the_store_keep_projects_apart(store, monkeypatch) -> None:
    put_secret(1, "a", {"k": "one"})
    put_secret(2, "a", {"k": "two"})
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-test-p{project_id}")
    get_settings.cache_clear()
    assert secret_store.read_secret(1, "a", "k") == "one"
    # Even if AnsiDeck's own path building were bypassed, project 1's token can't read 2's.
    real = secret_store._api_path
    monkeypatch.setattr(
        secret_store,
        "_api_path",
        lambda *segments: real(*[("2" if s == "1" else s) for s in segments]),
    )
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(1, "a", "k")
    assert error.value.kind == "denied"


def test_a_deleted_secret_is_not_found_and_a_revoked_token_logs_in_again(store) -> None:
    put_secret(1, "gone", {"k": "v"})
    assert secret_store.read_secret(1, "gone", "k") == "v"
    token = secret_store._client._token.value
    with _admin() as bao:
        assert bao.post("/v1/auth/token/revoke", json={"token": token}).status_code == 204
        assert bao.delete(f"/v1/secret/data/{PREFIX}/1/gone").status_code == 204
    put_secret(1, "kept", {"k": "w"})
    assert secret_store.read_secret(1, "kept", "k") == "w"  # a fresh login
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(1, "gone", "k")
    assert error.value.kind == "not_found"


def test_with_project_policies_a_revoked_or_outdated_token_logs_in_again(
    store, monkeypatch
) -> None:
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-test-p{project_id}")
    get_settings.cache_clear()
    put_secret(1, "relogin", {"k": "one"})
    assert secret_store.read_secret(1, "relogin", "k") == "one"
    with _admin() as bao:
        token = secret_store._client._token.value
        assert bao.post("/v1/auth/token/revoke", json={"token": token}).status_code == 204
    assert secret_store.read_secret(1, "relogin", "k") == "one"  # the child token needs a login

    # A project whose policy the role only gets after AnsiDeck logged in (the setup re-run).
    put_secret(4, "relogin", {"k": "four"})
    role = "/v1/auth/approle/role/ansideck-test"
    with _admin() as bao:
        policies = bao.get(role).json()["data"]["token_policies"]
        rules = f'path "secret/data/{PREFIX}/4/*" {{ capabilities = ["read"] }}\n'
        assert (
            bao.put("/v1/sys/policies/acl/ansideck-test-p4", json={"policy": rules}).status_code
            == 204
        )
        assert (
            bao.post(role, json={"token_policies": [*policies, "ansideck-test-p4"]}).status_code
            == 204
        )
    try:
        assert secret_store.read_secret(4, "relogin", "k") == "four"
    finally:
        with _admin() as bao:
            bao.post(role, json={"token_policies": policies})


def _sentinel_rows(sentinel: str) -> list[str]:
    hits = []
    with get_engine().connect() as conn:
        for table in Base.metadata.sorted_tables:
            rows = conn.execute(
                text(f'SELECT row_to_json(t)::text FROM "{table.name}" t')
            ).scalars()
            hits += [table.name for row in rows if sentinel in row]
    return hits


def test_a_run_uses_a_stored_key_and_vault_password_and_stores_neither(
    store, client, tmp_path
) -> None:
    _login(client)
    key = _generate_key_pem()
    password = f"stored-vault-pw-{uuid.uuid4().hex[:8]}"
    put_secret(1, "runs/ssh", {"private_key": key})
    put_secret(1, "runs/vault", {"password": password})
    credential = client.post(
        "/api/credentials", json={"name": "stored-key", "store_path": "runs/ssh"}
    )
    assert credential.status_code == 201, credential.text
    assert credential.json()["store_location"] == f"secret/{PREFIX}/1/runs/ssh#private_key"
    vault = client.post(
        "/api/vault-passwords", json={"name": "stored-vault", "store_path": "runs/vault"}
    )
    assert vault.status_code == 201, vault.text
    check = client.post(f"/api/credentials/{credential.json()['id']}/check").json()
    assert check["ok"] and check["version"] >= 1

    encrypted = client.post(
        "/api/vault/encrypt",
        json={
            "vault_password_id": vault.json()["id"],
            "plaintext": "from-the-store",
            "var_name": "secret_value",
        },
    )
    assert encrypted.status_code == 200, encrypted.text
    playbook = _create_playbook(client, _vault_var_playbook(encrypted.json()["yaml_block"]))
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook,
            "inventory_id": inventory_id,
            "credential_id": credential.json()["id"],
            "vault_password_id": vault.json()["id"],
        },
    ).json()
    done = _wait_for_completion(client, run["id"])
    assert done["status"] == "success", done
    assert (tmp_path / "marker.txt").read_text() == "from-the-store"

    marker = key.splitlines()[1]  # a line of the key's body
    assert _sentinel_rows(marker) == [] and _sentinel_rows(password) == []
    log = (tmp_path / "runs" / f"{run['id']}.jsonl").read_text()
    assert password not in log and marker not in log


def test_a_reference_must_exist_and_be_a_key(store, client) -> None:
    _login(client)
    put_secret(1, "notakey", {"private_key": "hello"})
    for body, message in (
        ({"store_path": "missing/x"}, "no secret at that path"),
        ({"store_path": "../2/x"}, "invalid path"),
        ({"store_path": "notakey"}, "Invalid private key"),
    ):
        response = client.post("/api/credentials", json={"name": "bad", **body})
        assert response.status_code == 400 and message in response.json()["detail"], response.text


def test_a_store_outage_fails_runs_with_a_reason_and_alerts_once(
    store, client, tmp_path, monkeypatch
) -> None:
    _login(client)
    put_secret(1, "outage/ssh", {"private_key": _generate_key_pem()})
    credential = client.post(
        "/api/credentials", json={"name": "outage-key", "store_path": "outage/ssh"}
    ).json()
    playbook = _create_playbook(
        client, "- hosts: all\n  connection: local\n  gather_facts: false\n  tasks: []\n"
    )
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    monkeypatch.setenv("SECRETS_STORE_URL", "http://127.0.0.1:1")  # nothing listens there
    get_settings.cache_clear()
    secret_store.reset()
    runs = [
        client.post(
            "/api/runs",
            json={
                "playbook_id": playbook,
                "inventory_id": inventory_id,
                "credential_id": credential["id"],
            },
        ).json()
        for _ in range(2)
    ]
    for run in runs:
        done = _wait_for_completion(client, run["id"])
        assert done["status"] == "failed"
        assert done["status_reason"] == (
            "not run: could not read credential 'outage-key' from OpenBao: "
            "the secret store can't be reached"
        )
    assert _store_alerts() == ["secrets.unavailable"]  # once, though two runs failed

    monkeypatch.setenv("SECRETS_STORE_URL", ADDR)
    get_settings.cache_clear()
    secret_store.reset()
    _probe_secret_store()
    assert _store_alerts() == []
    assert secret_store.status()["ok"] is True


def _store_alerts() -> list[str]:
    db = get_sessionmaker()()
    try:
        return list(
            db.scalars(
                select(NotificationAlert.key).where(NotificationAlert.key == "secrets.unavailable")
            )
        )
    finally:
        db.close()
