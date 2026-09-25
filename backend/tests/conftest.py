import os
from collections.abc import Generator

from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())

# Tests get their own database, dropped and recreated per session. The name must end in
# "_test" so a mistyped URL can never wipe a real database.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://ansideck:ansideck@localhost:5433/ansideck_test"
)
if not (make_url(TEST_DATABASE_URL).database or "").endswith("_test"):
    raise RuntimeError(
        f"TEST_DATABASE_URL must name a database ending in _test: {TEST_DATABASE_URL}"
    )
os.environ["DATABASE_URL"] = TEST_DATABASE_URL  # wins over any .env

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.bootstrap import seed_fresh_install  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.crypto import hash_password  # noqa: E402
from app.db import Base, get_engine, get_sessionmaker, init_db  # noqa: E402
from app.hardening import (  # noqa: E402
    api_key_ip_throttle,
    ip_login_throttle,
    sso_ip_throttle,
    totp_user_throttle,
    user_login_throttle,
)
from app.main import app  # noqa: E402
from app.models import Project, ProjectMember, User  # noqa: E402


def reset_engine() -> None:
    """Drops the cached engine (closing its pool) so the next use builds a fresh one."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def _test_database() -> Generator[None, None, None]:
    url = make_url(TEST_DATABASE_URL)
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
        conn.execute(
            text(
                f"CREATE DATABASE \"{url.database}\" TEMPLATE template0 ENCODING 'UTF8' "
                "LOCALE_PROVIDER builtin BUILTIN_LOCALE 'C.UTF-8'"
            )
        )
    admin.dispose()
    get_settings.cache_clear()
    reset_engine()
    init_db()  # the migrations themselves are part of every test run
    yield
    reset_engine()


def truncate_all() -> None:
    tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with get_engine().begin() as conn:
        conn.execute(text("SET LOCAL lock_timeout = '20s'"))
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.fixture
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()

    user_login_throttle.clear()
    ip_login_throttle.clear()
    api_key_ip_throttle.clear()
    sso_ip_throttle.clear()
    totp_user_throttle.clear()
    truncate_all()

    seed_db = get_sessionmaker()()
    seed_fresh_install(seed_db)
    seed_db.close()

    yield TestClient(app)

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
