"""The secret store client (app.secret_store), against a mock transport: paths can't leave a
project's subtree, logins and retries, every answer mapped to an error kind, the time budget,
and nothing secret in logs or errors."""

import inspect
import json
import logging
import os
import time

import httpx
import pytest
from pydantic import ValidationError

from app import secret_store
from app.config import Settings, get_settings
from app.secret_store import SecretStoreError
from app.worker import __main__ as worker_main
from app.worker import client as worker_client

ROOT = "http://bao.test:8200"
VALUE = "-----BEGIN OPENSSH PRIVATE KEY-----\nsentinel-key-value\n-----END OPENSSH PRIVATE KEY-----"


@pytest.fixture
def store(monkeypatch, tmp_path):
    """A configured token-auth store; returns a dict to steer the mock and see requests."""
    token_file = tmp_path / "token"
    token_file.write_text("tok-sentinel-1\n")
    for name, value in {
        "SECRETS_STORE_URL": ROOT,
        "SECRETS_STORE_AUTH": "token",
        "SECRETS_STORE_TOKEN_FILE": str(token_file),
    }.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    secret_store.reset()
    state = {
        "requests": [],
        "secrets": {"/v1/secret/data/ansideck/7/web/ssh": {"private_key": VALUE, "n": 5}},
        "status": {},
        "once": {},  # like status, for one request only
        "token_file": token_file,
        "tmp": tmp_path,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        path = request.url.raw_path.decode()
        if path in state["once"]:
            code, body = state["once"].pop(path)
            return httpx.Response(code, json=body)
        if path in state["status"]:
            code, body = state["status"][path]
            return httpx.Response(code, json=body)
        if path.startswith("/v1/auth/approle/login"):
            body = json.loads(request.content)
            if body["secret_id"] != "sid-sentinel":
                return httpx.Response(400, json={"errors": ["invalid role or secret ID"]})
            state["logins"] = state.get("logins", 0) + 1
            return httpx.Response(
                200,
                json={
                    "auth": {"client_token": f"approle-{state['logins']}", "lease_duration": 600}
                },
            )
        if path == "/v1/auth/token/create":
            body = json.loads(request.content)
            state["child_request"] = body
            return httpx.Response(200, json={"auth": {"client_token": "child-token"}})
        if path in state["secrets"]:
            return httpx.Response(
                200, json={"data": {"data": state["secrets"][path], "metadata": {"version": 3}}}
            )
        return httpx.Response(404, json={"errors": []})

    monkeypatch.setattr(secret_store, "default_transport", httpx.MockTransport(handler))
    yield state
    secret_store.reset()
    get_settings.cache_clear()


def test_a_reference_reads_from_the_projects_own_subtree(store) -> None:
    assert secret_store.read_versioned(7, "web/ssh", "private_key") == (VALUE, 3)
    request = store["requests"][-1]
    assert request.url.raw_path == b"/v1/secret/data/ansideck/7/web/ssh"
    assert request.headers["X-Vault-Token"] == "tok-sentinel-1"
    assert (
        secret_store.location(7, "web/ssh", "private_key")
        == "secret/ansideck/7/web/ssh#private_key"
    )


@pytest.mark.parametrize(
    "path",
    [
        "../8/web/ssh",
        "web/../../8/x",
        "web/./ssh",
        ".hidden",
        "-flag",
        "web//ssh",
        "/web/ssh",
        "web/ssh/",
        "web%2fssh",
        "%2e%2e/8",
        "web\x00ssh",
        "web\n",  # `$` alone would match before a trailing newline
        "web/ssh\n",
        "wéb",
        "web ssh",
        "",
        "a/" * 17 + "a",
        "x" * 401,
    ],
)
def test_paths_that_could_leave_the_subtree_are_refused(store, path: str) -> None:
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, path, "private_key")
    assert error.value.kind == "invalid"
    assert store["requests"] == []  # refused before anything is sent


@pytest.mark.parametrize("key", ["", "..", "a/b", "-k", "k y", "k\n"])
def test_bad_keys_are_refused(store, key: str) -> None:
    with pytest.raises(SecretStoreError, match="invalid"):
        secret_store.read_secret(7, "web/ssh", key)


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (403, {"errors": ["permission denied"]}, "denied"),
        (404, {"errors": []}, "not_found"),
        (503, {"errors": ["Vault is sealed"]}, "sealed"),
        (503, {"errors": ["standby"]}, "unreachable"),
        (500, {"errors": ["internal"]}, "bad_response"),
        (307, {}, "bad_response"),  # a redirect (the store "cleaning" a path) is never followed
        (200, {"data": {"data": None, "metadata": {"deletion_time": "x"}}}, "not_found"),
        (200, {"data": {"data": {"other": "v"}}}, "missing_key"),
        (200, {"data": {"data": {"private_key": 12}}}, "bad_value"),
        (200, {"data": {"data": {"private_key": ""}}}, "bad_value"),
        (200, {"nope": 1}, "bad_response"),
    ],
)
def test_answers_map_to_error_kinds(store, status: int, body: dict, kind: str) -> None:
    store["status"]["/v1/secret/data/ansideck/7/web/ssh"] = (status, body)
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == kind
    assert "permission denied" not in str(error.value).lower() or kind == "denied"


def test_an_unreachable_store_is_retried_once_within_the_budget(store, monkeypatch) -> None:
    calls = []

    def down(request):
        calls.append(request)
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(secret_store, "default_transport", httpx.MockTransport(down))
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "unreachable" and len(calls) == 2


def test_a_spent_budget_stops_before_asking(store) -> None:
    with pytest.raises(SecretStoreError, match="didn't answer within"):
        secret_store.read_secret(7, "web/ssh", "private_key", deadline=time.monotonic() - 1)
    assert store["requests"] == []


def test_an_untrusted_certificate_is_a_tls_error(store, monkeypatch) -> None:
    def bad_cert(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    monkeypatch.setattr(secret_store, "default_transport", httpx.MockTransport(bad_cert))
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "tls"


def test_the_token_file_is_reread_when_it_changes(store) -> None:
    secret_store.read_secret(7, "web/ssh", "private_key")
    store["token_file"].write_text("tok-sentinel-2\n")
    os.utime(store["token_file"], (time.time() + 5, time.time() + 5))
    secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["requests"][-1].headers["X-Vault-Token"] == "tok-sentinel-2"


def _approle(monkeypatch, store, secret_id: str = "sid-sentinel") -> None:
    sid = store["tmp"] / "secret_id"
    sid.write_text(secret_id + "\n")
    monkeypatch.setenv("SECRETS_STORE_AUTH", "approle")
    monkeypatch.setenv("SECRETS_STORE_ROLE_ID", "role-1")
    monkeypatch.setenv("SECRETS_STORE_SECRET_ID_FILE", str(sid))
    get_settings.cache_clear()
    secret_store.reset()


def test_approle_logs_in_once_and_again_near_expiry(store, monkeypatch) -> None:
    _approle(monkeypatch, store)
    secret_store.read_secret(7, "web/ssh", "private_key")
    secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["logins"] == 1
    assert store["requests"][-1].headers["X-Vault-Token"] == "approle-1"
    secret_store._client._token.refresh_at = time.monotonic() - 1  # two thirds of its life gone
    secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["logins"] == 2


def test_approle_logs_in_again_once_after_a_403(store, monkeypatch) -> None:
    """A revoked token looks like a denial: one fresh login, then a real denial stays one."""
    _approle(monkeypatch, store)
    secret_store.read_secret(7, "web/ssh", "private_key")
    store["status"]["/v1/secret/data/ansideck/7/web/ssh"] = (403, {"errors": ["permission denied"]})
    with pytest.raises(SecretStoreError, match="permission denied"):
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["logins"] == 2


def test_a_wrong_secret_id_is_an_auth_failure(store, monkeypatch) -> None:
    _approle(monkeypatch, store, secret_id="wrong")
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "auth_failed"


def test_the_project_policy_reads_through_a_one_use_child_token(store, monkeypatch) -> None:
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-project-{project_id}")
    get_settings.cache_clear()
    secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["child_request"] == {
        "policies": ["ansideck-project-7"],
        "ttl": "30s",
        "num_uses": 1,
        "no_default_policy": True,
        "renewable": False,
        "display_name": "ansideck-project-7",
    }
    assert store["requests"][-1].headers["X-Vault-Token"] == "child-token"


@pytest.mark.parametrize(
    ("code", "why"),
    [(403, "a revoked token"), (400, "a token from before the role got this project's policy")],
)
def test_approle_logs_in_again_once_when_a_child_token_is_refused(
    store, monkeypatch, code, why
) -> None:
    _approle(monkeypatch, store)
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-project-{project_id}")
    get_settings.cache_clear()
    secret_store.read_secret(7, "web/ssh", "private_key")
    store["once"]["/v1/auth/token/create"] = (code, {"errors": [why]})
    assert secret_store.read_secret(7, "web/ssh", "private_key") == VALUE
    assert store["logins"] == 2
    assert store["requests"][-1].headers["X-Vault-Token"] == "child-token"


def test_a_child_token_refused_after_a_fresh_login_stays_denied(store, monkeypatch) -> None:
    _approle(monkeypatch, store)
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-project-{project_id}")
    get_settings.cache_clear()
    store["status"]["/v1/auth/token/create"] = (400, {"errors": ["policies not a subset"]})
    with pytest.raises(SecretStoreError, match="'ansideck-project-7' is not available") as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "denied" and store["logins"] == 2


def test_a_token_file_does_not_retry_a_refused_child_token(store, monkeypatch) -> None:
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-project-{project_id}")
    get_settings.cache_clear()
    store["status"]["/v1/auth/token/create"] = (400, {"errors": ["policies not a subset"]})
    with pytest.raises(SecretStoreError):
        secret_store.read_secret(7, "web/ssh", "private_key")
    creates = [r for r in store["requests"] if r.url.path == "/v1/auth/token/create"]
    assert len(creates) == 1


def test_the_namespace_header_is_sent(store, monkeypatch) -> None:
    monkeypatch.setenv("SECRETS_STORE_NAMESPACE", "team-a")
    get_settings.cache_clear()
    secret_store.read_secret(7, "web/ssh", "private_key")
    assert store["requests"][-1].headers["X-Vault-Namespace"] == "team-a"


def test_nothing_secret_reaches_logs_or_errors(store, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    secret_store.read_secret(7, "web/ssh", "private_key")
    store["status"]["/v1/secret/data/ansideck/7/web/ssh"] = (500, {"errors": [VALUE]})
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    for text in (caplog.text, str(error.value)):
        assert "sentinel-key-value" not in text and "tok-sentinel" not in text


def test_disabled_store(store, monkeypatch) -> None:
    monkeypatch.delenv("SECRETS_STORE_URL")
    get_settings.cache_clear()
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "disabled"


def test_the_probe_reports_health_and_token_ttl(store) -> None:
    store["status"]["/v1/sys/health"] = (200, {"sealed": False, "version": "2.7.1"})
    store["status"]["/v1/auth/token/lookup-self"] = (200, {"data": {"ttl": 1200}})
    result = secret_store.probe()
    assert result["ok"] and result["version"] == "2.7.1" and result["token_ttl"] == 1200
    store["status"]["/v1/sys/health"] = (503, {"sealed": True})
    sealed = secret_store.probe()
    assert (sealed["ok"], sealed["error_kind"]) == (False, "sealed")
    assert secret_store.status()["last_ok_at"] == result["checked_at"]


# ---------------------------------------------------------------- configuration


def _settings(**values) -> Settings:
    return Settings(_env_file=None, **values)


def test_the_store_settings_are_checked(tmp_path, monkeypatch) -> None:
    token = tmp_path / "token"
    token.write_text("t")
    good = {"secrets_store_url": "https://bao.lan:8200", "secrets_store_token_file": str(token)}
    assert _settings(**good).secrets_store_enabled
    for bad, message in (
        ({"secrets_store_url": "ftp://x"}, "https://"),
        ({"secrets_store_token_file": str(tmp_path / "missing")}, "readable"),
        ({"secrets_store_kv_mount": "a/b"}, "one path segment"),
        ({"secrets_store_path_prefix": ".."}, "one path segment"),
        ({"secrets_store_auth": "approle"}, "ROLE_ID"),
        ({"secrets_store_project_policy": "fixed-name"}, "{project_id}"),
        ({"secrets_store_project_policy": "p-{project_id}-{x}"}, "{project_id}"),
        ({"secrets_store_timeout_seconds": 15}, "less than or equal"),
    ):
        with pytest.raises(ValidationError, match=message):
            _settings(**{**good, **bad})
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_SECRET_KEY", "a-real-secret-value")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://ansideck:s3cret-db@db/ansideck")
    monkeypatch.setenv("WORKER_TOKEN", "w" * 32)
    with pytest.raises(ValidationError, match="https"):
        _settings(**{**good, "secrets_store_url": "http://bao.lan:8200"})
    assert _settings(**{**good, "secrets_store_url": "http://127.0.0.1:8200"}).secrets_store_enabled


def test_the_store_budget_fits_the_workers_job_timeout() -> None:
    """build_job runs while the worker waits for /job (15 s): one job's reads must finish
    well before, or the worker retries into a run that already started."""
    worker_timeout = inspect.signature(worker_client.ApiClient.post).parameters["timeout"].default
    metadata = Settings.model_fields["secrets_store_timeout_seconds"].metadata
    budget = max(m.le for m in metadata if hasattr(m, "le"))
    assert budget <= worker_timeout - 5


def test_a_worker_refuses_store_credentials(monkeypatch) -> None:
    for name in ("SECRETS_STORE_TOKEN_FILE", "SECRETS_STORE_SECRET_ID_FILE", "VAULT_TOKEN"):
        monkeypatch.setenv(name, "x")
    assert {"SECRETS_STORE_TOKEN_FILE", "SECRETS_STORE_SECRET_ID_FILE", "VAULT_TOKEN"} <= set(
        worker_main.forbidden_env()
    )


def test_the_request_goes_out_exactly_as_built(store, monkeypatch) -> None:
    """Defense in depth: even a path that slipped past validation can't be collapsed by
    httpx into another project's path."""
    monkeypatch.setattr(secret_store, "check_path", lambda path: path.split("/"))
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/../../8/ssh", "private_key")
    assert error.value.kind == "invalid"
    assert store["requests"] == []


def test_a_redirect_to_another_project_is_not_followed(store) -> None:
    store["secrets"]["/v1/secret/data/ansideck/8/web/ssh"] = {"private_key": "project-8-key"}

    def redirect(request: httpx.Request) -> httpx.Response:
        if request.url.raw_path == b"/v1/secret/data/ansideck/7/web/ssh":
            return httpx.Response(307, headers={"Location": "/v1/secret/data/ansideck/8/web/ssh"})
        return httpx.Response(
            200, json={"data": {"data": {"private_key": "project-8-key"}, "metadata": {}}}
        )

    secret_store.default_transport = httpx.MockTransport(redirect)
    with pytest.raises(SecretStoreError) as error:
        secret_store.read_secret(7, "web/ssh", "private_key")
    assert error.value.kind == "bad_response"
