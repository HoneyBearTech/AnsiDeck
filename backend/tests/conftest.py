import os
from collections.abc import Generator

from cryptography.fernet import Fernet

os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.bootstrap import seed_admin_user  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.crypto import hash_password  # noqa: E402
from app.db import get_engine, get_sessionmaker, init_db  # noqa: E402
from app.hardening import ip_login_throttle, user_login_throttle  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Project, ProjectMember, User  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()

    user_login_throttle.clear()
    ip_login_throttle.clear()
    init_db()

    seed_db = get_sessionmaker()()
    seed_admin_user(seed_db)
    seed_db.close()

    yield TestClient(app)

    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    get_settings.cache_clear()


TEST_PASSWORD = "a-long-test-password-1"


def make_user_client(
    username: str, role: str, password: str = TEST_PASSWORD, default_membership: bool = True
) -> TestClient:
    """A separate TestClient (own cookie jar) logged in as a freshly created user."""
    db = get_sessionmaker()()
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    if role != "admin" and default_membership:
        default = db.query(Project).filter(Project.name == "Default").one()
        db.add(ProjectMember(project_id=default.id, user_id=user.id, role=role))
        db.commit()
    db.close()
    user_client = TestClient(app)
    response = user_client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return user_client


@pytest.fixture
def admin_client(client: TestClient) -> TestClient:
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )
    return client


@pytest.fixture
def operator_client(client: TestClient) -> TestClient:
    return make_user_client("operator1", "operator")


@pytest.fixture
def viewer_client(client: TestClient) -> TestClient:
    return make_user_client("viewer1", "viewer")
