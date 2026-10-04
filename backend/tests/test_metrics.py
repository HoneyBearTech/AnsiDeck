"""Prometheus metrics (app.metrics, app.metrics_api): off without a token, token-protected,
low-cardinality labels, nothing secret, and the numbers move when runs do."""

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from pydantic import ValidationError
from sqlalchemy import text

from app import metrics
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.internal_api import internal_app
from app.main import app
from app.metrics_api import _read, database_collector, metrics_app, metrics_ip_throttle
from app.models import AuditEvent, NotificationAlert
from tests.conftest import make_user_client
from tests.routes import iter_api_routes
from tests.test_runs import (
    FAILURE_PLAYBOOK,
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _wait_for_completion,
)

TOKEN = "m" * 40
ALLOWED_LABELS = {
    "project_id",
    "project",  # ansideck_project_info only
    "status",
    "worker",
    "route",
    "method",
    "server",
    "action",
    "outcome",
    "kind",
    "state",
    "trigger",
    "version",
    "le",
}


@pytest.fixture
def scrape(client, monkeypatch):
    """Turns metrics on and returns a function that scrapes them: {(sample name, labels): value}."""
    monkeypatch.setenv("METRICS_TOKEN", TOKEN)
    get_settings.cache_clear()
    metrics_ip_throttle.clear()
    http = TestClient(metrics_app, headers={"Authorization": f"Bearer {TOKEN}"})

    def read(raw: bool = False):
        database_collector.invalidate()
        response = http.get("/metrics")
        assert response.status_code == 200, response.text
        if raw:
            return response.text
        return {
            (sample.name, frozenset(sample.labels.items())): sample.value
            for family in text_string_to_metric_families(response.text)
            for sample in family.samples
        }

    return read


def value(samples: dict, name: str, **labels) -> float:
    return samples.get((name, frozenset(labels.items())), 0.0)


def _trigger(client, playbook: str, tmp_path, name: str = "m", **extra) -> int:
    playbook_id = _create_playbook(client, playbook, name=f"{name}.yml")
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "marker.txt"), name=name)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name=name),
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_metrics_token_settings(monkeypatch) -> None:
    assert Settings(_env_file=None).metrics_token == ""  # off by default
    with pytest.raises(ValidationError, match="METRICS_TOKEN must differ"):
        Settings(_env_file=None, metrics_token=Settings(_env_file=None).worker_token)
    with pytest.raises(ValidationError, match="METRICS_TOKEN must differ"):
        Settings(_env_file=None, metrics_token="k" * 40, auth_secret_key="k" * 40)
    assert Settings(_env_file=None, metrics_token="short").metrics_token == "short"  # dev

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_SECRET_KEY", "a-real-secret-value")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://ansideck:s3cret-db@db/ansideck")
    monkeypatch.setenv("WORKER_TOKEN", "w" * 32)
    with pytest.raises(ValidationError, match="METRICS_TOKEN of at least 32 characters"):
        Settings(_env_file=None, metrics_token="m" * 31)
    assert Settings(_env_file=None, metrics_token="m" * 32).metrics_token == "m" * 32


def test_without_a_token_nothing_is_served(client, monkeypatch) -> None:
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    get_settings.cache_clear()
    metrics_ip_throttle.clear()
    # "Bearer " would match an empty token: an unset token must refuse everyone.
    for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Bearer x"}):
        assert TestClient(metrics_app).get("/metrics", headers=headers).status_code == 401


def test_wrong_tokens_are_refused_audited_and_throttled(scrape) -> None:
    http = TestClient(metrics_app)
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}):
        assert http.get("/metrics", headers=headers).status_code == 401
    db = get_sessionmaker()()
    try:
        failures = db.query(AuditEvent).filter(AuditEvent.action == "metrics.auth_failed").all()
        assert len(failures) == 3
        assert {e.outcome for e in failures} == {"failure"}
    finally:
        db.close()

    for _ in range(17):
        http.get("/metrics", headers={"Authorization": "Bearer wrong"})
    good = {"Authorization": f"Bearer {TOKEN}"}
    assert http.get("/metrics", headers=good).status_code == 429  # even the right token, now


def test_metrics_live_only_on_their_own_app(scrape) -> None:
    public = TestClient(app)
    assert public.get("/metrics").status_code == 404
    assert public.get("/api/metrics").status_code == 404
    http = TestClient(metrics_app, headers={"Authorization": f"Bearer {TOKEN}"})
    for path in ("/", "/docs", "/redoc", "/openapi.json", "/metrics/x"):
        assert http.get(path).status_code == 404, path
    assert http.get("/metrics").headers["content-type"].startswith("text/plain")


def test_runs_show_up_in_the_metrics(admin_client, scrape, tmp_path) -> None:
    before = scrape()
    project = ("project_id", "1")
    finished = lambda s, status: value(  # noqa: E731
        s, "ansideck_runs_finished_total", project_id="1", status=status
    )

    ok = _trigger(admin_client, SUCCESS_PLAYBOOK, tmp_path)
    assert _wait_for_completion(admin_client, ok)["status"] == "success"
    bad = _trigger(admin_client, FAILURE_PLAYBOOK, tmp_path, name="bad")
    assert _wait_for_completion(admin_client, bad)["status"] == "failed"
    after = scrape()

    assert finished(after, "success") - finished(before, "success") == 1
    assert finished(after, "failed") - finished(before, "failed") == 1
    queued = "ansideck_runs_queued_total"
    assert (
        value(after, queued, project_id="1", trigger="user")
        - value(before, queued, project_id="1", trigger="user")
        == 2
    )
    for histogram, labels in (
        ("ansideck_run_duration_seconds_count", {"project_id": "1"}),
        ("ansideck_run_queue_wait_seconds_count", {}),
    ):
        assert value(after, histogram, **labels) - value(before, histogram, **labels) == 2

    # Database gauges, read at scrape time.
    assert value(after, "ansideck_db_up") == 1
    assert value(after, "ansideck_project_info", project_id="1", project="Default") == 1
    assert value(after, "ansideck_runs", project_id="1", status="queued") == 0
    assert value(after, "ansideck_runs", project_id="1", status="running") == 0
    assert (("ansideck_runs", frozenset({project, ("status", "queued")}))) in after
    assert value(after, "ansideck_worker_slots", worker="test-worker") == 4
    assert value(after, "ansideck_worker_online", worker="test-worker") == 1
    assert value(after, "ansideck_workers", state="online") == 1
    assert value(after, "ansideck_slots", state="total") == 4
    assert value(after, "ansideck_queue_oldest_age_seconds") == 0
    assert value(after, "ansideck_ops_alerts", kind="queue.stuck") == 0
    assert value(after, "ansideck_build_info", version="0.1.0") == 1

    # HTTP metrics: by route template, public and internal.
    run_route = dict(server="public", method="GET", route="/api/runs/{run_id}", status="200")
    assert value(after, "ansideck_http_requests_total", **run_route) >= 2
    claim = dict(server="internal", method="POST", route="/internal/claim")
    assert value(after, "ansideck_http_request_duration_seconds_count", **claim) >= 2


@pytest.mark.no_worker
def test_a_queued_run_that_never_started_counts_without_a_duration(
    admin_client, scrape, tmp_path
) -> None:
    run_id = _trigger(admin_client, SUCCESS_PLAYBOOK, tmp_path)
    waiting = scrape()
    assert value(waiting, "ansideck_runs", project_id="1", status="queued") == 1
    assert value(waiting, "ansideck_queue_oldest_age_seconds") > 0
    assert value(waiting, "ansideck_workers", state="online") == 0

    assert admin_client.post(f"/api/runs/{run_id}/cancel").status_code == 200
    after = scrape()
    cancelled = dict(project_id="1", status="cancelled")
    assert (
        value(after, "ansideck_runs_finished_total", **cancelled)
        - value(waiting, "ansideck_runs_finished_total", **cancelled)
        == 1
    )
    duration = "ansideck_run_duration_seconds_count"
    assert value(after, duration, project_id="1") == value(waiting, duration, project_id="1")
    assert value(after, "ansideck_runs", project_id="1", status="queued") == 0


def test_route_labels_are_templates_never_raw_paths(admin_client, scrape) -> None:
    admin_client.get("/api/runs/123456")  # 404, but the route matched
    admin_client.get("/garbage/../etc/passwd-sentinel")
    samples = scrape()
    routes = {dict(labels).get("route") for _, labels in samples} - {None}
    # Pins FastAPI's private effective_route_context: without it these would be "/{run_id}".
    assert "/api/runs/{run_id}" in routes
    assert "unmatched" in routes
    public = {getattr(r, "path_format", r.path) for r in iter_api_routes(app)}
    internal = set(internal_app.openapi()["paths"])
    assert routes <= public | internal | {"unmatched"}, routes - public - internal


def test_labels_are_bounded_and_nothing_secret_leaks(admin_client, scrape, tmp_path) -> None:
    sentinel_user = make_user_client("sentinel-user-zq", "operator")
    sentinel_user.get("/api/runs")
    playbook_id = _create_playbook(admin_client, SUCCESS_PLAYBOOK, name="sentinel-playbook-zq.yml")
    inventory = admin_client.post("/api/inventories", json={"name": "sentinel-inventory-zq"})
    inventory_id = inventory.json()["id"]
    admin_client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "sentinel-host-zq", "vars": {"marker_path": str(tmp_path / "m")}},
    )
    run = admin_client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(admin_client, name="sentinel-cred-zq"),
            "extra_vars": {"token": "sentinel-extra-var-zq"},
            "limit": "sentinel-host-zq",
        },
    )
    assert _wait_for_completion(admin_client, run.json()["id"])["status"] == "success"
    admin_client.post("/api/auth/login", json={"username": "sentinel-login-zq", "password": "x"})

    body = scrape(raw=True)
    assert "zq" not in body
    assert TOKEN not in body
    for family in text_string_to_metric_families(body):
        if not family.name.startswith("ansideck_"):
            continue  # the client library's own process/python metrics
        for sample in family.samples:
            assert set(sample.labels) <= ALLOWED_LABELS, (sample.name, sample.labels)
            if "project" in sample.labels:
                assert family.name == "ansideck_project_info"


def test_lockouts_and_audit_events_are_counted(client, scrape) -> None:
    before = scrape()
    for _ in range(6):
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    after = scrape()
    login = dict(action="auth.login", outcome="failure")
    assert (
        value(after, "ansideck_audit_events_total", **login)
        - value(before, "ansideck_audit_events_total", **login)
        >= 5
    )
    assert (
        value(after, "ansideck_login_lockouts_total")
        - value(before, "ansideck_login_lockouts_total")
        >= 1
    )


def test_odd_audit_actions_and_outcomes_collapse_to_other() -> None:
    def count(action: str, outcome: str) -> float:
        return metrics.AUDIT_EVENTS.labels(action, outcome)._value.get()

    before = count("other", "other")
    metrics.audit_recorded("Not An Action/../x", "weird", locked_out=False)
    assert count("other", "other") == before + 1


def test_notification_attempts_are_counted_by_outcome() -> None:
    def count(outcome: str) -> float:
        return metrics.NOTIFICATION_DELIVERIES.labels("webhook", outcome)._value.get()

    before = {o: count(o) for o in ("sent", "retry", "failed")}
    for status in ("sent", "pending", "failed", "sending"):  # "sending" is not an outcome
        metrics.notification_attempted("webhook", status)
    assert {o: count(o) - before[o] for o in before} == {"sent": 1, "retry": 1, "failed": 1}


def test_raised_ops_alerts_and_the_outbox_are_gauged(client, scrape) -> None:
    db = get_sessionmaker()()
    try:
        db.add(NotificationAlert(key="worker.offline:host-a:1"))
        db.add(NotificationAlert(key="worker.offline:host-b:2"))
        db.add(NotificationAlert(key="queue.stuck"))
        db.commit()
    finally:
        db.close()
    samples = scrape()
    assert value(samples, "ansideck_ops_alerts", kind="worker.offline") == 2
    assert value(samples, "ansideck_ops_alerts", kind="queue.stuck") == 1
    # Always present, so dashboards sum over zeros rather than missing series.
    assert ("ansideck_ops_alerts", frozenset({("kind", "worker.unisolated")})) in samples
    assert value(samples, "ansideck_notification_outbox", status="pending") == 0


def test_a_database_failure_still_serves_the_process_metrics(scrape, monkeypatch) -> None:
    def broken(db):
        raise RuntimeError("database is down")

    monkeypatch.setattr("app.metrics_api._read", broken)
    samples = scrape()
    assert value(samples, "ansideck_db_up") == 0
    assert not any(name == "ansideck_runs" for name, _ in samples)
    assert any(name == "ansideck_build_info" for name, _ in samples)


def test_scrapes_are_read_only_and_time_limited(client) -> None:
    db = get_sessionmaker()()
    try:
        _read(db)
        assert db.execute(text("SHOW transaction_read_only")).scalar() == "on"
        assert db.execute(text("SHOW statement_timeout")).scalar() == "3s"
    finally:
        db.rollback()
        db.close()


def test_counters_count_only_committed_work(client) -> None:
    seen: list[str] = []
    db = get_sessionmaker()()
    try:
        db.execute(text("SELECT 1"))
        metrics.after_commit(db, lambda: seen.append("rolled back"))
        db.rollback()
        db.commit()
        assert seen == []

        db.execute(text("SELECT 1"))
        metrics.after_commit(db, lambda: seen.append("committed"))
        try:
            with db.begin_nested():  # a failed savepoint doesn't drop the outer work
                raise ValueError
        except ValueError:
            pass
        assert seen == []
        db.commit()
        assert seen == ["committed"]

        db.execute(text("SELECT 1"))
        metrics.after_commit(db, lambda: seen.append("closed"))
        db.close()
        db.execute(text("SELECT 1"))
        db.commit()
        assert seen == ["committed"]
    finally:
        db.close()


def test_route_template_falls_back_to_unmatched() -> None:
    assert metrics.route_template({}) == "unmatched"
    assert metrics.route_template({"fastapi": {}}) == "unmatched"

    class Route:
        path_format = "/internal/ping"

    assert metrics.route_template({"route": Route()}) == "/internal/ping"
