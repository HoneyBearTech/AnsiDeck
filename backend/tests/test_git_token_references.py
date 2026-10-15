"""A git source's HTTPS token from the secret store (git_sources.token_store_path/key): checked
once when it is set, read at each sync and test, never stored here; switching between a stored
token and a reference clears the other."""

import pytest
from fastapi.testclient import TestClient

from app import git_sync
from app.db import get_sessionmaker
from app.models import GitSource
from tests.conftest import make_user_client
from tests.test_runs import _login
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

URL = "https://git.example/org/repo.git"
TOKEN = "git-token-sentinel-123"
SECRET = "/v1/secret/data/ansideck/1/git/infra"


def _row(source_id: int) -> GitSource:
    db = get_sessionmaker()()
    try:
        row = db.get(GitSource, source_id)
        db.expunge(row)
        return row
    finally:
        db.close()


def _create(client: TestClient, **body):
    return client.post(
        "/api/projects/1/git-sources",
        json={"name": "infra", "url": URL, "auth_kind": "https_token", **body},
    )


@pytest.mark.no_worker
def test_a_token_reference_is_checked_and_never_stored(client: TestClient, store) -> None:  # noqa: F811
    _login(client)
    store["secrets"][SECRET] = {"token": TOKEN, "other": "x"}
    created = _create(client, token_store_path="git/infra")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["has_token"] is True and body["token_store"] == "external"
    assert body["token_location"] == "secret/ansideck/1/git/infra#token"
    row = _row(body["id"])
    assert row.encrypted_token is None and (row.token_store_path, row.token_store_key) == (
        "git/infra",
        "token",
    )
    assert TOKEN not in created.text
    seen = make_user_client("v1", "viewer").get(f"/api/projects/1/git-sources/{body['id']}").json()
    assert seen["has_token"] is True and seen["token_store"] == "external"
    assert (seen["token_store_path"], seen["token_store_key"], seen["token_location"]) == (
        None,
    ) * 3

    db = get_sessionmaker()()
    auth = git_sync.auth_for(db, db.get(GitSource, body["id"]))
    db.close()
    assert auth.token == TOKEN  # read at sync time

    store["secrets"][SECRET] = {"token": "rotated-token-456"}
    db = get_sessionmaker()()
    assert git_sync.auth_for(db, db.get(GitSource, body["id"])).token == "rotated-token-456"
    store["status"][SECRET] = (503, {"errors": ["Vault is sealed"]})
    with pytest.raises(git_sync.SyncError, match="could not read the token from the secret store"):
        git_sync.auth_for(db, db.get(GitSource, body["id"]))
    db.close()


@pytest.mark.no_worker
def test_a_reference_must_exist_and_comes_alone(client: TestClient, store) -> None:  # noqa: F811
    _login(client)
    missing = _create(client, token_store_path="git/nope")
    assert missing.status_code == 400 and "no secret at that path" in missing.text
    store["secrets"][SECRET] = {"token": TOKEN}
    wrong_key = _create(client, token_store_path="git/infra", token_store_key="pat")
    assert wrong_key.status_code == 400 and "no such key" in wrong_key.text
    both = _create(client, token_store_path="git/infra", token="also-a-token")
    assert both.status_code == 400 and "not both" in both.text
    outside = _create(client, token_store_path="../2/git")
    assert outside.status_code == 400


@pytest.mark.no_worker
def test_switching_between_a_token_and_a_reference_clears_the_other(
    client: TestClient,
    store,  # noqa: F811
) -> None:
    _login(client)
    store["secrets"][SECRET] = {"pat": TOKEN}
    source = _create(client, token="stored-token-789").json()
    assert source["token_store"] == "ansideck" and source["token_location"] is None
    url = f"/api/projects/1/git-sources/{source['id']}"

    to_store = client.patch(url, json={"token_store_path": "git/infra", "token_store_key": "pat"})
    assert to_store.status_code == 200, to_store.text
    row = _row(source["id"])
    assert row.encrypted_token is None and row.token_store_key == "pat"

    back = client.patch(url, json={"token": "new-stored-token"})
    assert back.json()["token_store"] == "ansideck"
    assert _row(source["id"]).token_store_path is None

    client.patch(url, json={"token_store_path": "git/infra", "token_store_key": "pat"})
    public = client.patch(url, json={"auth_kind": "none"})
    assert public.json()["token_store"] is None and public.json()["has_token"] is False
    row = _row(source["id"])
    assert row.token_store_path is None and row.encrypted_token is None
