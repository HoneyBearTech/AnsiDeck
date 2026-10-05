"""Notifications (Phase 4D-1): destinations, rendering, the outbox, the dispatcher and the
channels API. Nothing here reaches the network: DNS is faked and HTTP goes to a MockTransport."""

import hashlib
import hmac
import ipaddress
import json
import smtplib

import httpx
import pytest
from sqlalchemy import select, text, update

from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.models import AuditEvent, NotificationChannel, NotificationDelivery, Run
from app.notifications import RUN_FAILED, RUN_RECOVERED, dispatch, render, safe_http
from app.notifications import channels as channel_mod
from app.notifications.channels import ConfigError, seal, validate
from app.notifications.safe_http import DestinationError
from app.routers.notifications import test_send_throttle
from tests.conftest import internal_client
from tests.test_internal_api import Claimed
from tests.test_projects import _member, _project
from tests.test_reaper import _same_run
from tests.test_runs import _login

PUBLIC_IP = "93.184.215.14"
DNS = {
    "hooks.slack.com": PUBLIC_IP,
    "discord.com": PUBLIC_IP,
    "example.com": PUBLIC_IP,
    "api.pushbullet.com": PUBLIC_IP,
    "api.pushover.net": PUBLIC_IP,
    "lan.example": "192.168.1.20",
    "localhost": "127.0.0.1",
    "metadata.example": "169.254.169.254",
    "ula.example": "fd00::1",
    "mapped.example": "::ffff:10.0.0.1",
    "cgnat.example": "100.64.0.1",
}
SLACK = "https://hooks.slack.com/services/T000/B000/secret-token-abcd"
DISCORD = "https://discord.com/api/webhooks/123/secret-token-wxyz"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    def resolve(host: str, port: int):
        if host not in DNS:
            raise DestinationError(f"cannot resolve {host}", retryable=True)
        return [ipaddress.ip_address(DNS[host])]

    monkeypatch.setattr(safe_http, "_resolve", resolve)


class Sink:
    """Records requests; answers with `status` (and headers)."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 204
        self.headers: dict[str, str] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, headers=self.headers)

    def json(self, n: int = -1) -> dict:
        return json.loads(self.requests[n].content)


@pytest.fixture
def sink(monkeypatch) -> Sink:
    sink = Sink()
    monkeypatch.setattr(safe_http, "default_transport", httpx.MockTransport(sink.handler))
    return sink


@pytest.fixture
def settings_env(monkeypatch):
    """Sets env vars for get_settings() and refreshes it."""

    def apply(**values: str) -> None:
        for name, value in values.items():
            monkeypatch.setenv(name, value)
        get_settings.cache_clear()

    yield apply
    get_settings.cache_clear()


# ------------------------------------------------------------------ destinations


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/hook",
        "https://lan.example/hook",
        "https://metadata.example/latest",
        "https://ula.example/hook",
        "https://mapped.example/hook",
        "https://cgnat.example/hook",
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
    ],
)
def test_non_public_destinations_are_refused(url: str) -> None:
    with pytest.raises(DestinationError, match="non-public address"):
        safe_http.check(url, [])


def test_destination_rules() -> None:
    assert safe_http.check("https://example.com/x?y=1", []).path == "/x?y=1"
    for url, message in (
        ("http://example.com/hook", "must use https"),
        ("ftp://example.com/hook", "must start with https"),
        ("https://user:pw@example.com/hook", "user name or password"),
        ("https://nowhere.example/hook", "cannot resolve"),
        ("https://example.com:99999/hook", "invalid port"),
    ):
        with pytest.raises(DestinationError, match=message):
            safe_http.check(url, [])


def test_the_allowlist_admits_named_hosts_and_networks() -> None:
    assert safe_http.check("http://lan.example/hook", ["lan.example"]).address == (
        ipaddress.ip_address("192.168.1.20")
    )
    assert safe_http.check("https://lan.example/hook", ["192.168.0.0/16"])
    with pytest.raises(DestinationError):
        safe_http.check("https://lan.example/hook", ["10.0.0.0/8", "other.example"])


def test_requests_go_to_the_checked_address_without_redirects(sink: Sink) -> None:
    sink.status, sink.headers = 302, {"Location": "http://127.0.0.1/"}
    response = safe_http.post("https://example.com:8443/hook?a=1", b"{}", {}, [])
    assert response.status_code == 302  # not followed
    [request] = sink.requests
    assert str(request.url) == f"https://{PUBLIC_IP}:8443/hook?a=1"
    assert request.headers["Host"] == "example.com:8443"
    assert request.extensions["sni_hostname"] == "example.com"


# ------------------------------------------------------------------ rendering

FAILED = {
    "run_id": 7,
    "project": "Ops",
    "playbook": "site.yml",
    "inventory": "prod",
    "group": None,
    "triggered_by": "alice",
    "status": "failed",
    "reason": None,
    "hosts": {"total": 3, "ok": 1, "changed": 0, "failed": 1, "unreachable": 1},
    "failed_tasks": [{"host": "web1", "task": "restart nginx"}],
}


def test_a_failed_run_message_has_the_summary_and_failed_tasks() -> None:
    message = render.build(RUN_FAILED, FAILED, "https://ansideck.example")
    assert message.title == "Run #7 failed: site.yml on prod"
    assert ("Hosts", "1 ok, 1 failed, 1 unreachable (of 3)") in message.facts
    assert message.items == ["web1: restart nginx"]
    assert message.url == "https://ansideck.example/runs/7"
    assert render.build(RUN_FAILED, {**FAILED, "status": "timed_out"}).title.startswith(
        "Run #7 timed out"
    )
    assert render.build(RUN_RECOVERED, FAILED).title == "Run #7 recovered: site.yml on prod"
    assert render.build(RUN_FAILED, FAILED).url is None  # no PUBLIC_URL, no link


def test_discord_never_pings_and_escapes_markdown() -> None:
    payload = {**FAILED, "triggered_by": "@everyone **bold**"}
    body = render.discord(render.build(RUN_FAILED, payload))
    assert body["allowed_mentions"] == {"parse": []}
    [embed] = body["embeds"]
    assert {"name": "Triggered by", "value": "@everyone \\*\\*bold\\*\\*", "inline": True} in (
        embed["fields"]
    )


def test_slack_escapes_its_control_characters() -> None:
    body = render.slack(render.build(RUN_FAILED, {**FAILED, "triggered_by": "<!channel> & co"}))
    text = json.dumps(body)
    assert "<!channel>" not in text and "&lt;!channel&gt; &amp; co" in text


def test_teams_gets_an_adaptive_card() -> None:
    body = render.teams(render.build(RUN_FAILED, FAILED, "https://a.example"))
    [attachment] = body["attachments"]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["text"].startswith("Run #7")
    assert card["actions"][0]["url"] == "https://a.example/runs/7"


def test_webhooks_are_signed_with_timestamp_and_body() -> None:
    body = b'{"event":"run.failed"}'
    headers = render.signature_headers(body, "s3cret", now=1700000000)
    expected = hmac.new(b"s3cret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert headers == {
        "X-AnsiDeck-Timestamp": "1700000000",
        "X-AnsiDeck-Signature": f"sha256={expected}",
    }
    assert "X-AnsiDeck-Signature" not in render.signature_headers(body, None)


def test_email_and_push_bodies_stay_plain_and_bounded() -> None:
    subject, text_body = render.email(render.build(RUN_FAILED, {**FAILED, "playbook": "a\nb"}))
    assert "\n" not in subject and subject.startswith("[AnsiDeck] Run #7 failed")
    assert "  - web1: restart nginx" in text_body
    many = {**FAILED, "failed_tasks": [{"host": f"h{i}", "task": "x" * 150} for i in range(10)]}
    push = render.pushover(render.build(RUN_FAILED, many), "tok", "usr")
    assert len(push["message"]) <= 1024 and push["token"] == "tok"
    assert (
        render.pushbullet(render.build(RUN_FAILED, FAILED, "https://a.example"))["type"] == "link"
    )


# ------------------------------------------------------------------ channel config


def test_channel_urls_are_checked_per_kind(settings_env) -> None:
    settings = get_settings()
    assert validate("slack", {"url": SLACK}, settings) == {"url": SLACK}
    assert validate("webhook", {"url": "https://example.com/h", "secret": "s"}, settings) == {
        "url": "https://example.com/h",
        "secret": "s",
    }
    for kind, url, message in (
        ("slack", "https://example.com/hook", "hooks.slack.com"),
        ("discord", "https://example.com/api/webhooks/1/x", "discord.com/api/webhooks"),
        ("teams", "http://example.com/x", "https://"),
        ("webhook", "https://lan.example/x", "non-public"),
        ("webhook", "", "required"),
    ):
        with pytest.raises(ConfigError, match=message):
            validate(kind, {"url": url}, settings)
    with pytest.raises(ConfigError, match="SMTP_HOST"):
        validate("email", {"recipients": ["a@example.com"]}, settings)
    with pytest.raises(ConfigError, match="Pushover needs"):
        validate("pushover", {"token": "abcdefgh123"}, settings)


def test_email_channels_need_valid_recipients(settings_env) -> None:
    settings_env(SMTP_HOST="mail.example", SMTP_FROM="ansideck@example.com")
    settings = get_settings()
    assert validate("email", {"recipients": [" a@example.com "]}, settings) == {
        "recipients": ["a@example.com"]
    }
    for recipients in ([], ["not-an-address"], ["a@example.com\r\nBcc: x@evil.example"]):
        with pytest.raises(ConfigError):
            validate("email", {"recipients": recipients}, settings)


def test_smtp_settings_are_checked() -> None:
    with pytest.raises(ValueError, match="SMTP_FROM"):
        Settings(credential_encryption_key="k", smtp_host="mail.example")
    with pytest.raises(ValueError, match="SMTP_TLS=none"):
        Settings(
            credential_encryption_key="k",
            environment="production",
            auth_secret_key="x" * 40,
            admin_password="y" * 20,
            database_url="postgresql+psycopg://a:strong@db/x",
            worker_token="w" * 40,
            smtp_host="mail.example",
            smtp_from="a@example.com",
            smtp_tls="none",
        )


class FakeSMTP:
    sent: list = []
    calls: list = []

    def __init__(self, host, port, timeout=None, context=None) -> None:
        FakeSMTP.calls.append(("connect", type(self).__name__, host, port))

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        pass

    def starttls(self, context=None) -> None:
        FakeSMTP.calls.append(("starttls",))

    def login(self, user, password) -> None:
        FakeSMTP.calls.append(("login", user))

    def send_message(self, message) -> None:
        FakeSMTP.sent.append(message)


class FakeSMTPSSL(FakeSMTP):
    pass


@pytest.mark.parametrize(
    ("tls", "expected"),
    [
        ("starttls", [("connect", "FakeSMTP", "mail.example", 587), ("starttls",), ("login", "u")]),
        ("tls", [("connect", "FakeSMTPSSL", "mail.example", 587), ("login", "u")]),
        ("none", [("connect", "FakeSMTP", "mail.example", 587), ("login", "u")]),
    ],
)
def test_email_is_sent_through_the_configured_server(monkeypatch, settings_env, tls, expected):
    settings_env(
        SMTP_HOST="mail.example",
        SMTP_FROM="ansideck@example.com",
        SMTP_USERNAME="u",
        SMTP_PASSWORD="p",
        SMTP_TLS=tls,
    )
    FakeSMTP.sent, FakeSMTP.calls = [], []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    channel = NotificationChannel(
        kind="email", config_encrypted=seal({"recipients": ["a@b.example"]})
    )
    outcome = channel_mod.send(channel, RUN_FAILED, FAILED, get_settings())
    assert outcome.ok
    assert FakeSMTP.calls == expected
    [message] = FakeSMTP.sent
    assert message["To"] == "a@b.example" and message["Subject"].startswith("[AnsiDeck] Run #7")


# ------------------------------------------------------------------ outbox


def _channel(project_id: int | None, kind: str = "slack", events=(RUN_FAILED,), **extra) -> int:
    config = {"url": SLACK} if kind == "slack" else {"url": "https://example.com/hook"}
    db = get_sessionmaker()()
    try:
        channel = NotificationChannel(
            project_id=project_id,
            name=extra.pop("name", f"{kind}-{project_id}-{len(events)}"),
            kind=kind,
            config_encrypted=seal({**config, **extra.pop("config", {})}),
            events=list(events),
            created_by="admin",
            **extra,
        )
        db.add(channel)
        db.commit()
        return channel.id
    finally:
        db.close()


def _deliveries() -> list[NotificationDelivery]:
    db = get_sessionmaker()()
    try:
        return list(db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.id)))
    finally:
        db.close()


def _project_of(run_id: int) -> int:
    db = get_sessionmaker()()
    try:
        return db.get(Run, run_id).project_id
    finally:
        db.close()


def _finish(claimed: Claimed, status: str, failed_task: str | None = None) -> None:
    seq = 0
    if failed_task:
        event = {
            "event": "runner_on_failed",
            "counter": 1,
            "event_data": {"host": "web1", "task": failed_task, "ignore_errors": False},
        }
        ignored = {
            "event": "runner_on_failed",
            "counter": 2,
            "event_data": {"host": "web2", "task": "ignored", "ignore_errors": True},
        }
        assert (
            claimed.post("events", {"first_seq": 1, "events": [event, ignored]}).status_code == 200
        )
        seq = 2
    body = {"last_seq": seq, "status": status, "return_code": 0 if status == "success" else 2}
    assert claimed.post("complete", body).status_code == 200


@pytest.mark.no_worker
def test_a_failed_run_queues_one_delivery_per_subscribed_channel(client) -> None:
    claimed = Claimed(client)
    project = _project_of(claimed.run_id)
    mine = _channel(project)
    everywhere = _channel(None, name="global")
    _channel(project, name="recoveries only", events=(RUN_RECOVERED,))
    _channel(project, name="off", enabled=False)
    _login(client)
    other = _project(client, "Elsewhere")
    _channel(other, name="other project")

    _finish(claimed, "failed", failed_task="restart nginx")

    deliveries = _deliveries()
    assert {(d.channel_id, d.event, d.status) for d in deliveries} == {
        (mine, RUN_FAILED, "pending"),
        (everywhere, RUN_FAILED, "pending"),
    }
    payload = deliveries[0].payload
    assert payload["run_id"] == claimed.run_id and payload["status"] == "failed"
    assert "url" not in json.dumps(payload)


@pytest.mark.no_worker
def test_a_success_after_a_failure_is_a_recovery_and_other_endings_are_quiet(client) -> None:
    first = Claimed(client)
    channel = _channel(_project_of(first.run_id), events=(RUN_FAILED, RUN_RECOVERED))
    _finish(first, "success")  # no earlier run: nothing
    assert _deliveries() == []

    def again(status: str) -> None:
        client.post("/api/runs", json=_same_run(client, first.run_id))
        claim = internal_client().post(
            "/internal/claim", json={"worker_id": "w", "wait_seconds": 0}
        )
        claimed = Claimed.__new__(Claimed)
        claimed.http, claimed.run_id = internal_client(), claim.json()["run_id"]
        claimed.claim_token = claim.json()["claim_token"]
        _finish(claimed, status)

    again("failed")
    again("cancelled")  # a cancel neither alerts nor resets the failure
    again("success")
    again("success")  # already fine: quiet
    assert [(d.channel_id, d.event) for d in _deliveries()] == [
        (channel, RUN_FAILED),
        (channel, RUN_RECOVERED),
    ]


@pytest.mark.no_worker
def test_runs_the_reaper_ends_are_reported_too(client) -> None:
    claimed = Claimed(client)
    _channel(_project_of(claimed.run_id))
    db = get_sessionmaker()()
    db.execute(
        update(Run)
        .where(Run.id == claimed.run_id)
        .values(lease_expires_at=text("now() - interval '1 second'"))
    )
    db.commit()
    db.close()
    from app.reaper import reap_once

    assert reap_once() == [claimed.run_id]
    [delivery] = _deliveries()
    assert delivery.event == RUN_FAILED
    assert delivery.payload["reason"].startswith("worker lost")


# ------------------------------------------------------------------ dispatcher


def _due_now() -> None:
    db = get_sessionmaker()()
    db.execute(update(NotificationDelivery).values(next_attempt_at=text("now() - interval '1 s'")))
    db.execute(update(NotificationDelivery).values(sent_at=text("now() - interval '1 hour'")))
    db.commit()
    db.close()


def _seconds_until_next_attempt(delivery_id: int) -> float:
    db = get_sessionmaker()()
    try:
        return db.scalar(
            text(
                "SELECT extract(epoch FROM next_attempt_at - now()) "
                "FROM notification_deliveries WHERE id = :i"
            ),
            {"i": delivery_id},
        )
    finally:
        db.close()


@pytest.mark.no_worker
def test_the_dispatcher_sends_with_the_failed_tasks(client, sink: Sink, tmp_path) -> None:
    claimed = Claimed(client)
    _channel(_project_of(claimed.run_id))
    _finish(claimed, "failed", failed_task="restart nginx")
    assert dispatch.dispatch_once() == 1
    [delivery] = _deliveries()
    assert (delivery.status, delivery.attempts, delivery.last_status_code) == ("sent", 1, 204)
    assert delivery.payload["failed_tasks"] == [{"host": "web1", "task": "restart nginx"}]
    [request] = sink.requests
    assert request.headers["Host"] == "hooks.slack.com"
    assert "restart nginx" in request.content.decode() and "ignored" not in request.content.decode()


def _queue_one(project_id=None, kind="slack", **extra) -> int:
    channel = _channel(project_id, kind=kind, **extra)
    db = get_sessionmaker()()
    delivery = NotificationDelivery(channel_id=channel, event=RUN_FAILED, payload=FAILED)
    db.add(delivery)
    db.commit()
    delivery_id = delivery.id
    db.close()
    return delivery_id


@pytest.mark.no_worker
def test_failures_are_retried_with_backoff_and_retry_after(client, sink: Sink) -> None:
    delivery_id = _queue_one()
    sink.status = 500
    dispatch.dispatch_once()
    [delivery] = _deliveries()
    assert (delivery.status, delivery.attempts, delivery.last_error) == ("pending", 1, "HTTP 500")
    assert 25 < _seconds_until_next_attempt(delivery_id) <= 30

    _due_now()
    sink.status, sink.headers = 429, {"Retry-After": "7"}
    dispatch.dispatch_once()
    assert 5 < _seconds_until_next_attempt(delivery_id) <= 7

    _due_now()
    sink.status, sink.headers = 200, {}
    dispatch.dispatch_once()
    [delivery] = _deliveries()
    assert (delivery.status, delivery.attempts) == ("sent", 3)


@pytest.mark.no_worker
def test_permanent_errors_and_exhausted_retries_fail(client, sink: Sink) -> None:
    _queue_one()
    sink.status = 404
    dispatch.dispatch_once()
    assert _deliveries()[0].status == "failed"

    db = get_sessionmaker()()
    db.query(NotificationDelivery).delete()
    db.commit()
    db.close()
    _queue_one(name="second")
    sink.status = 502
    for _ in range(dispatch.MAX_ATTEMPTS):
        _due_now()
        dispatch.dispatch_once()
    [delivery] = _deliveries()
    assert (delivery.status, delivery.attempts) == ("failed", dispatch.MAX_ATTEMPTS)


@pytest.mark.no_worker
def test_a_refused_destination_fails_without_sending(client, sink: Sink) -> None:
    _queue_one(kind="webhook", config={"url": "https://lan.example/hook"})
    dispatch.dispatch_once()
    [delivery] = _deliveries()
    assert delivery.status == "failed" and delivery.last_error.startswith("refused: lan.example")
    assert sink.requests == []


@pytest.mark.no_worker
def test_a_host_that_does_not_resolve_is_retried(client, sink: Sink) -> None:
    # e.g. a self-hosted receiver that is restarting (found by the compose E2E)
    _queue_one(kind="webhook", config={"url": "https://gone.example/hook"})
    dispatch.dispatch_once()
    [delivery] = _deliveries()
    assert (delivery.status, delivery.last_error) == ("pending", "cannot resolve gone.example")


@pytest.mark.no_worker
def test_sends_to_one_channel_are_paced(client, sink: Sink) -> None:
    channel = _channel(None)
    db = get_sessionmaker()()
    for _ in range(2):
        db.add(NotificationDelivery(channel_id=channel, event=RUN_FAILED, payload=FAILED))
    db.commit()
    db.close()
    dispatch.dispatch_once()
    assert [d.status for d in _deliveries()] == ["sent", "pending"]
    assert len(sink.requests) == 1


@pytest.mark.no_worker
def test_a_send_interrupted_by_a_crash_is_retried_after_its_lease(client, sink: Sink) -> None:
    _queue_one()
    db = get_sessionmaker()()
    assert len(dispatch.claim(db)) == 1  # ...and then the process died
    db.close()
    assert dispatch.dispatch_once() == 0  # leased
    _due_now()
    assert dispatch.dispatch_once() == 1
    assert _deliveries()[0].status == "sent"


@pytest.mark.no_worker
def test_disabled_channels_and_old_deliveries(client, sink: Sink) -> None:
    _queue_one(enabled=False)
    dispatch.dispatch_once()
    assert _deliveries()[0].status == "failed" and sink.requests == []
    db = get_sessionmaker()()
    db.execute(update(NotificationDelivery).values(created_at=text("now() - interval '31 days'")))
    assert dispatch.prune(db) == 1
    db.commit()
    db.close()


# ------------------------------------------------------------------ API


def _create(c, body: dict, project_id: int | None = None, expect: int = 201) -> dict:
    path = (
        "/api/notifications/channels"
        if project_id is None
        else f"/api/projects/{project_id}/notifications/channels"
    )
    response = c.post(path, json=body)
    assert response.status_code == expect, response.text
    return response.json()


def test_channels_never_show_their_secrets(client, sink: Sink) -> None:
    _login(client)
    created = _create(
        client,
        {
            "name": "hooks",
            "kind": "webhook",
            "url": "https://example.com/h/tok-1234",
            "secret": "sig-secret-9876",
            "events": [RUN_FAILED],
        },
    )
    assert created["target"] == "https://example.com/…1234" and created["has_secret"] is True
    for response in (
        client.get("/api/notifications/channels"),
        client.get(f"/api/notifications/channels/{created['id']}"),
        client.patch(f"/api/notifications/channels/{created['id']}", json={"name": "renamed"}),
        client.get("/api/audit", params={"action": "notification_channel.create"}),
    ):
        assert response.status_code == 200
        assert "tok-1234" not in response.text and "sig-secret-9876" not in response.text

    # PATCH without secrets keeps them; a new URL is checked like a new channel's.
    client.post(f"/api/notifications/channels/{created['id']}/test")
    assert sink.requests[-1].headers["X-AnsiDeck-Signature"].startswith("sha256=")
    bad = client.patch(
        f"/api/notifications/channels/{created['id']}", json={"url": "https://lan.example/x"}
    )
    assert bad.status_code == 422 and "non-public" in bad.json()["detail"]
    cleared = client.patch(f"/api/notifications/channels/{created['id']}", json={"secret": ""})
    assert cleared.json()["has_secret"] is False


def test_test_send_logs_and_is_throttled(client, sink: Sink) -> None:
    test_send_throttle.clear()
    _login(client)
    channel = _create(client, {"name": "s", "kind": "slack", "url": SLACK, "events": [RUN_FAILED]})
    result = client.post(f"/api/notifications/channels/{channel['id']}/test").json()
    assert result == {"ok": True, "status_code": 204, "error": None}
    assert "AnsiDeck test notification" in sink.requests[0].content.decode()
    [entry] = client.get(f"/api/notifications/channels/{channel['id']}/deliveries").json()
    assert (entry["event"], entry["status"], entry["title"]) == (
        "test",
        "sent",
        "AnsiDeck test notification",
    )
    for _ in range(4):
        client.post(f"/api/notifications/channels/{channel['id']}/test")
    assert client.post(f"/api/notifications/channels/{channel['id']}/test").status_code == 429
    test_send_throttle.clear()


def test_channel_validation(client, settings_env) -> None:
    _login(client)
    base = {"name": "x", "kind": "slack", "url": SLACK}
    assert "unknown event" in _create(client, {**base, "events": ["nope"]}, expect=422)["detail"]
    _create(client, {**base, "events": [RUN_FAILED]})
    _create(client, {**base, "events": [RUN_FAILED]}, expect=409)
    assert (
        "SMTP_HOST"
        in _create(
            client,
            {
                "name": "mail",
                "kind": "email",
                "recipients": ["a@example.com"],
                "events": [RUN_FAILED],
            },
            expect=422,
        )["detail"]
    )
    catalog = client.get("/api/notifications/catalog").json()
    assert catalog["email_available"] is False and "pushover" in catalog["kinds"]
    assert {e["name"] for e in catalog["events"]} >= {RUN_FAILED, RUN_RECOVERED}


def test_project_admins_manage_only_their_projects_channels(client) -> None:
    admin = client
    _login(admin)
    a, b = _project(admin, "A"), _project(admin, "B")
    body = {"name": "x", "kind": "slack", "url": SLACK, "events": [RUN_FAILED]}
    in_b = _create(admin, body, project_id=b)
    in_global = _create(admin, body)

    a_admin = _member(admin, "a-admin", {a: "admin"})
    a_operator = _member(admin, "a-operator", {a: "operator"})
    assert _create(a_admin, body, project_id=a)["project_id"] == a
    assert a_admin.get("/api/notifications/catalog").status_code == 200
    assert a_admin.get(f"/api/projects/{b}/notifications/channels").status_code == 404
    for method, path in (
        ("GET", f"/api/projects/{a}/notifications/channels/{in_b['id']}"),  # B's, via A
        ("PATCH", f"/api/projects/{a}/notifications/channels/{in_b['id']}"),
        ("DELETE", f"/api/projects/{a}/notifications/channels/{in_b['id']}"),
        ("POST", f"/api/projects/{a}/notifications/channels/{in_b['id']}/test"),
        ("GET", f"/api/projects/{a}/notifications/channels/{in_b['id']}/deliveries"),
        ("GET", f"/api/projects/{a}/notifications/channels/{in_global['id']}"),
    ):
        assert a_admin.request(method, path, json={}).status_code == 404, (method, path)
    assert a_admin.get("/api/notifications/channels").status_code == 403
    assert a_operator.get(f"/api/projects/{a}/notifications/channels").status_code == 403
    assert a_operator.get("/api/notifications/catalog").status_code == 403


def test_deleting_a_channel_is_audited_without_its_url(client) -> None:
    _login(client)
    channel = _create(
        client, {"name": "d", "kind": "discord", "url": DISCORD, "events": [RUN_FAILED]}
    )
    assert client.delete(f"/api/notifications/channels/{channel['id']}").status_code == 204
    db = get_sessionmaker()()
    try:
        events = db.query(AuditEvent).filter(AuditEvent.action.like("notification_channel.%")).all()
    finally:
        db.close()
    assert [e.action for e in events] == [
        "notification_channel.create",
        "notification_channel.delete",
    ]
    assert all("secret-token" not in json.dumps(e.detail) for e in events)
    assert events[0].detail == {"kind": "discord", "events": [RUN_FAILED], "enabled": True}


# ------------------------------------------------------------------ 4D-2: ops and security

GLOBAL_EVENTS = (
    "worker.offline",
    "worker.unisolated",
    "queue.stuck",
    "security.login_attack",
    "security.admin_change",
)


def _events_queued() -> list[tuple[str, dict]]:
    return [(d.event, d.payload) for d in _deliveries()]


def _heartbeat(worker_id: str, isolated: bool | None = True) -> None:
    body = {"worker_id": worker_id, "slots": 2, "runs": []}
    if isolated is not None:
        body["isolated"] = isolated
    assert internal_client().post("/internal/heartbeat", json=body).status_code == 200


def _set_worker_seen(worker_id: str, seconds_ago: int) -> None:
    db = get_sessionmaker()()
    db.execute(
        text("UPDATE workers SET last_seen_at = now() - make_interval(secs => :s) WHERE id = :i"),
        {"s": seconds_ago, "i": worker_id},
    )
    db.commit()
    db.close()


@pytest.mark.no_worker
def test_a_silent_worker_is_reported_once_and_its_return_too(client) -> None:
    from app.reaper import reap_once

    _channel(None, name="ops", events=GLOBAL_EVENTS)
    _heartbeat("w1")
    _set_worker_seen("w1", 60)  # offline on the Workers page, but under 2 min: no alert
    reap_once()
    assert _events_queued() == []

    _set_worker_seen("w1", 150)
    reap_once()
    reap_once()
    [(event, payload)] = _events_queued()
    assert (event, payload["state"], payload["worker"]) == ("worker.offline", "offline", "w1")

    _heartbeat("w1")
    _heartbeat("w1")
    assert [(e, p["state"]) for e, p in _events_queued()] == [
        ("worker.offline", "offline"),
        ("worker.offline", "resolved"),
    ]


@pytest.mark.no_worker
def test_a_worker_that_cannot_isolate_is_reported_once(client) -> None:
    _channel(None, name="ops", events=("worker.unisolated",))
    _heartbeat("dev", isolated=False)
    _heartbeat("dev", isolated=False)
    _heartbeat("old", isolated=None)  # a pre-4C worker doesn't say
    assert [(e, p["worker"]) for e, p in _events_queued()] == [("worker.unisolated", "dev")]


@pytest.mark.no_worker
def test_forgotten_workers_take_their_alerts_with_them(client) -> None:
    from app.models import NotificationAlert
    from app.reaper import reap_once

    _heartbeat("gone", isolated=False)
    _set_worker_seen("gone", 200)
    reap_once()
    _set_worker_seen("gone", 25 * 3600)
    reap_once()
    db = get_sessionmaker()()
    try:
        assert db.query(NotificationAlert).count() == 0
    finally:
        db.close()


def _age_queued(run_id: int, minutes: int) -> None:
    db = get_sessionmaker()()
    db.execute(
        update(Run)
        .where(Run.id == run_id)
        .values(queued_at=text(f"now() - interval '{minutes} minutes'"))
    )
    db.commit()
    db.close()


@pytest.mark.no_worker
def test_a_queue_stuck_without_workers_is_reported_once_and_when_it_moves(client) -> None:
    from app.reaper import reap_once
    from tests.test_queue import _queue_runs

    _channel(None, name="ops", events=("queue.stuck",))
    [[run_id]] = _queue_runs(client, 1, 1).values()
    _age_queued(run_id, 5)
    reap_once()
    assert _events_queued() == []  # not long enough yet

    _age_queued(run_id, 11)
    reap_once()
    reap_once()
    [(event, payload)] = _events_queued()
    assert (payload["state"], payload["waiting"], payload["oldest_run_id"]) == ("stuck", 1, run_id)
    assert payload["reason"].startswith("No worker is online")

    db = get_sessionmaker()()
    db.execute(update(Run).where(Run.id == run_id).values(status="cancelled"))
    db.commit()
    db.close()
    reap_once()
    assert [p["state"] for _e, p in _events_queued()] == ["stuck", "resolved"]


@pytest.mark.no_worker
def test_waiting_behind_the_same_inventory_is_not_stuck(client) -> None:
    from app.reaper import reap_once

    _channel(None, name="ops", events=("queue.stuck",))
    claimed = Claimed(client)  # running, holds the inventory
    _heartbeat("w")
    second = client.post("/api/runs", json=_same_run(client, claimed.run_id)).json()["id"]
    _age_queued(second, 30)
    reap_once()
    assert _events_queued() == []


def test_a_login_attack_is_reported_once_per_window(client) -> None:
    _channel(None, name="security", events=("security.login_attack",))
    for _ in range(8):  # the 5th locks the user out; later ones are refused before auditing
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    [(event, payload)] = _events_queued()
    assert (event, payload["kind"], payload["user"]) == (
        "security.login_attack",
        "password",
        "admin",
    )

    for _ in range(2):  # a wrong worker token, twice: one alert per address and window
        assert internal_client(token="w" * 40).post("/internal/ping", json={}).status_code == 401
    assert [p["kind"] for _e, p in _events_queued()] == ["password", "worker_token"]


def test_admin_changes_are_reported(client) -> None:
    _login(client)
    _channel(None, name="security", events=("security.admin_change",))
    _channel(None, name="runs only", events=(RUN_FAILED,))
    users = "/api/users"
    admin2 = client.post(users, json={"username": "boss", "password": "p" * 12, "role": "admin"})
    assert admin2.status_code == 201, admin2.text
    operator = client.post(
        users, json={"username": "oper", "password": "p" * 12, "role": "operator"}
    )
    assert operator.status_code == 201, operator.text
    client.patch(f"{users}/{operator.json()['id']}", json={"role": "viewer"})  # not admin: quiet
    client.patch(f"{users}/{operator.json()['id']}", json={"role": "admin"})
    client.patch(f"{users}/{admin2.json()['id']}", json={"role": "operator"})  # a demotion: quiet
    assert [(p["user"], p["change"], p["by"]) for _e, p in _events_queued()] == [
        ("boss", "created as a global admin", "admin"),
        ("oper", "made a global admin", "admin"),
    ]


def test_guessing_an_unknown_user_name_is_reported_too(client) -> None:
    # Found by the compose E2E: unknown names are audited as "(unknown user)", so the lockout
    # must be read off the audit event, not looked up in the throttle by name.
    _channel(None, name="security", events=("security.login_attack",))
    for _ in range(6):
        client.post("/api/auth/login", json={"username": "nobody-here", "password": "x"})
    [(event, payload)] = _events_queued()
    assert (payload["kind"], payload["user"]) == ("password", "(unknown user)")
    db = get_sessionmaker()()
    try:
        locked = db.query(AuditEvent).filter(AuditEvent.action == "auth.login").all()
    finally:
        db.close()
    assert [bool((e.detail or {}).get("locked_out")) for e in locked] == [False] * 4 + [True]


def test_a_second_factor_lockout_is_its_own_alert(client) -> None:
    from app import audit
    from app.models import User

    _channel(None, name="security", events=("security.login_attack",))
    db = get_sessionmaker()()
    try:
        admin = db.query(User).filter(User.username == "admin").one()
        detail = {"reason": "bad second factor", "locked_out": True}
        audit.record(
            db, "auth.login", outcome="failure", actor=admin, ip="198.51.100.7", detail=detail
        )
    finally:
        db.close()
    [(_event, payload)] = _events_queued()
    assert (payload["kind"], payload["user"]) == ("second_factor", "admin")
    message = render.build("security.login_attack", payload)
    assert message.title == "Repeated wrong 2FA codes for admin from 198.51.100.7"


def test_two_factor_and_sso_admin_changes_come_off_the_audit_trail(client) -> None:
    from app import audit
    from app.models import User

    _channel(None, name="security", events=("security.admin_change",))
    db = get_sessionmaker()()
    try:
        admin = db.query(User).filter(User.username == "admin").one()
        audit.record(db, "user.totp_reset", actor=admin, target_name="carol", ip="10.0.0.9")
        audit.record(db, "auth.totp_disable", actor=admin, ip="10.0.0.9")
        audit.record(db, "auth.login", actor=admin, ip="10.0.0.9", detail={"method": "oidc"})
        audit.record(db, "auth.login", actor=admin, ip="10.0.0.9")  # password: quiet
        audit.record(db, "user.totp_reset", outcome="failure", actor=admin, target_name="x")
    finally:
        db.close()
    assert [(p["user"], p["change"]) for _e, p in _events_queued()] == [
        ("carol", "had two-factor login reset"),
        ("admin", "turned off two-factor login"),
        ("admin", "signed in as a global admin with oidc"),
    ]


def test_ops_and_security_events_are_for_global_channels_only(client) -> None:
    _login(client)
    project = _project(client, "P")
    for event in GLOBAL_EVENTS:
        response = client.post(
            f"/api/projects/{project}/notifications/channels",
            json={"name": event, "kind": "slack", "url": SLACK, "events": [event]},
        )
        assert response.status_code == 422 and "global channels only" in response.json()["detail"]
    groups = {
        e["name"]: e["group"] for e in client.get("/api/notifications/catalog").json()["events"]
    }
    assert groups == {
        RUN_FAILED: "Runs",
        RUN_RECOVERED: "Runs",
        "inventory.refresh_failed": "Inventories",
        "worker.offline": "Operations",
        "worker.unisolated": "Operations",
        "queue.stuck": "Operations",
        "secrets.unavailable": "Operations",
        "security.login_attack": "Security",
        "security.admin_change": "Security",
    }


@pytest.mark.parametrize(
    ("event", "payload", "title", "color", "path"),
    [
        (
            "worker.offline",
            {"state": "offline", "worker": "w1", "slots": 2},
            "Worker w1 is offline",
            0xE5484D,
            "/workers",
        ),
        (
            "worker.offline",
            {"state": "resolved", "worker": "w1"},
            "Worker w1 is back online",
            0x30A46C,
            "/workers",
        ),
        (
            "worker.unisolated",
            {"worker": "w1"},
            "Worker w1 runs playbooks without isolation",
            0xE5484D,
            "/workers",
        ),
        (
            "secrets.unavailable",
            {"kind": "sealed", "label": "OpenBao"},
            "OpenBao is sealed",
            0xE5484D,
            "/workers",
        ),
        (
            "secrets.unavailable",
            {"state": "resolved", "label": "OpenBao"},
            "OpenBao works again",
            0x30A46C,
            "/workers",
        ),
        (
            "queue.stuck",
            {"state": "stuck", "waiting": 1, "minutes": 10},
            "Queue stuck: 1 run waiting over 10 min",
            0xE5484D,
            "/runs",
        ),
        (
            "queue.stuck",
            {"state": "stuck", "waiting": 3, "minutes": 10},
            "Queue stuck: 3 runs waiting over 10 min",
            0xE5484D,
            "/runs",
        ),
        ("queue.stuck", {"state": "resolved"}, "Queue moving again", 0x30A46C, "/runs"),
        (
            "security.login_attack",
            {"ip": "203.0.113.9", "kind": "password", "user": "admin"},
            "Login attack from 203.0.113.9",
            0xE5484D,
            "/audit",
        ),
        (
            "security.login_attack",
            {"ip": "203.0.113.9", "kind": "worker_token"},
            "Wrong worker token from 203.0.113.9",
            0xE5484D,
            "/audit",
        ),
        (
            "security.admin_change",
            {"user": "bob", "change": "made a global admin", "by": "alice"},
            "Admin change: bob made a global admin",
            0xE5484D,
            "/audit",
        ),
    ],
)
def test_ops_and_security_messages(event, payload, title, color, path) -> None:
    message = render.build(event, payload, "https://a.example")
    assert (message.title, message.color, message.url) == (title, color, f"https://a.example{path}")


def test_an_inventory_refresh_failure_and_its_all_clear_render() -> None:
    payload = {"inventory_id": 3, "inventory": "netbox", "project": "P", "error": "x" * 400}
    failed = render.build("inventory.refresh_failed", payload, "https://ansideck.example")
    assert failed.title == "Inventory netbox: refresh failed"
    assert failed.summary.endswith("Runs keep using the last good snapshot.")
    assert failed.url == "https://ansideck.example/inventories/3"
    resolved = render.build("inventory.refresh_failed", {**payload, "state": "resolved"})
    assert resolved.title == "Inventory netbox refreshes again" and resolved.url is None
