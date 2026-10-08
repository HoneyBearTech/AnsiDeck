"""What the public API answers to, and what it says back about a refused request."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.hardening import DEV_HOSTS, allowed_hosts
from app.main import app

SECRET = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETSECRET\n-----END OPENSSH PRIVATE KEY-----\n"


def test_allowed_hosts_default_to_the_dev_names_and_to_any_in_production() -> None:
    def settings(environment: str, hosts: list[str]) -> SimpleNamespace:
        return SimpleNamespace(environment=environment, allowed_hosts=hosts)

    assert allowed_hosts(settings("development", [])) == list(DEV_HOSTS)
    assert allowed_hosts(settings("production", [])) == ["*"]
    assert allowed_hosts(settings("production", ["deck.example"])) == ["deck.example"]


def test_a_request_for_another_host_is_refused(client: TestClient) -> None:
    """A DNS-rebinding page reaches the API with its own name in Host."""
    assert client.get("/api/health").status_code == 200  # TestClient's own host is allowed
    rebound = TestClient(app, base_url="http://rebound.example:8000")
    assert rebound.get("/api/health").status_code == 400
    assert rebound.post("/api/auth/login", json={}).status_code == 400


def test_a_refused_request_does_not_echo_what_was_sent(admin_client: TestClient) -> None:
    for path, body in (
        ("/api/credentials", {"private_key": SECRET}),  # no name
        ("/api/credentials", {"name": "x", "private_key": SECRET, "env": {"A": "b"}}),
        ("/api/credentials", {"name": "x", "env": {"TOKEN": ["SECRETSECRET"]}}),
        ("/api/vault-passwords", {"password": "SECRETSECRET"}),
    ):
        response = admin_client.post(path, json=body)
        assert response.status_code == 422, (path, response.text)
        assert "SECRETSECRET" not in response.text
        for error in response.json()["detail"]:
            assert set(error) <= {"loc", "msg", "type", "url"}
            assert error["msg"]


@pytest.mark.parametrize("origins", ['["*"]', '["https://*.example.com"]'])
def test_cors_origins_must_be_exact(monkeypatch, origins: str) -> None:
    """The API allows credentials, and a wildcard would let every site read it as the user."""
    monkeypatch.setenv("CORS_ORIGINS", origins)
    with pytest.raises(ValidationError, match="can't contain"):
        Settings(_env_file=None)
    monkeypatch.setenv("CORS_ORIGINS", '["https://deck.example.com"]')
    assert Settings(_env_file=None).cors_origins == ["https://deck.example.com"]
