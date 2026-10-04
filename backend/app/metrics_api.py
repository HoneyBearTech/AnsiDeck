"""The Prometheus endpoint: GET /metrics on a port of its own (METRICS_PORT, 8002), served
only when METRICS_TOKEN is set and only to requests that send it as a bearer token. Like the
internal worker API it is a separate app, so no reverse proxy in front of the public API can
expose it; never publish or proxy its port.

Besides app.metrics' in-process counters it reports gauges read from the database at scrape
time (queue, workers, notification outbox, raised ops alerts), cached for a few seconds so
several scrapers cost one set of queries. Totals that must survive restarts and project
deletions (history) are for the analytics views, not for Prometheus.
"""

import asyncio
import hmac
import logging
import threading
import time
from collections.abc import Iterator

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import get_sessionmaker
from app.hardening import FailureThrottle
from app.metrics import REGISTRY
from app.notifications import QUEUE_STUCK, WORKER_OFFLINE, WORKER_UNISOLATED
from app.queue import WORKER_ONLINE_SECONDS

logger = logging.getLogger(__name__)

CACHE_SECONDS = 5.0
STATEMENT_TIMEOUT_MS = 3000
# Worker ids come from whoever holds WORKER_TOKEN: cap the per-worker series.
MAX_WORKER_SERIES = 100
_WARN_EVERY_SECONDS = 60.0
_ALERT_KINDS = (WORKER_OFFLINE, WORKER_UNISOLATED, QUEUE_STUCK)

metrics_ip_throttle = FailureThrottle(max_failures=20, window_seconds=300)


def _gauge(name: str, doc: str, labels: tuple[str, ...] = ()) -> GaugeMetricFamily:
    return GaugeMetricFamily(name, doc, labels=list(labels))


def _read(db: Session) -> list[GaugeMetricFamily]:
    """Every database gauge, from one read-only transaction (index-backed or tiny tables)."""
    db.execute(text("SET TRANSACTION READ ONLY"))
    db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))

    def rows(sql: str, **params) -> list:
        return list(db.execute(text(sql), params).all())

    def one(sql: str, **params):
        return db.execute(text(sql), params).scalar()

    projects = rows("SELECT id, name FROM projects ORDER BY id")
    info = _gauge(
        "ansideck_project_info", "Project names by id (always 1)", ("project_id", "project")
    )
    for project_id, name in projects:
        info.add_metric([str(project_id), name], 1)

    active = {
        (project_id, run_status): count
        for project_id, run_status, count in rows(
            "SELECT project_id, status, count(*) FROM runs "
            "WHERE status IN ('queued', 'running') GROUP BY 1, 2"
        )
    }
    runs = _gauge("ansideck_runs", "Runs queued or running now", ("project_id", "status"))
    for project_id in sorted({p for p, _ in projects} | {p for p, _ in active}):
        for run_status in ("queued", "running"):
            runs.add_metric([str(project_id), run_status], active.get((project_id, run_status), 0))

    cancelling = _gauge("ansideck_runs_cancelling", "Running runs asked to stop")
    cancelling.add_metric(
        [],
        one(
            "SELECT count(*) FROM runs WHERE status = 'running' AND cancel_requested_at IS NOT NULL"
        ),
    )
    oldest = _gauge(
        "ansideck_queue_oldest_age_seconds", "How long the oldest queued run has waited (0: none)"
    )
    oldest.add_metric(
        [],
        float(
            one(
                "SELECT coalesce(extract(epoch FROM now() - min(queued_at)), 0) FROM runs "
                "WHERE status = 'queued'"
            )
        ),
    )

    workers = rows(
        """
        SELECT w.id, w.slots, w.isolated, extract(epoch FROM w.last_seen_at),
               w.last_seen_at > now() - make_interval(secs => :online),
               (SELECT count(*) FROM runs r WHERE r.status = 'running' AND r.worker_id = w.id)
        FROM workers w ORDER BY w.last_seen_at DESC, w.id
        """,
        online=WORKER_ONLINE_SECONDS,
    )
    by_state = _gauge(
        "ansideck_workers", "Workers seen in the last day, online or offline", ("state",)
    )
    online_count = sum(1 for w in workers if w[4])
    by_state.add_metric(["online"], online_count)
    by_state.add_metric(["offline"], len(workers) - online_count)
    per_worker = {
        "slots": _gauge("ansideck_worker_slots", "Run slots of a worker", ("worker",)),
        "busy": _gauge("ansideck_worker_busy_slots", "Runs a worker runs now", ("worker",)),
        "online": _gauge(
            "ansideck_worker_online",
            f"1 if the worker reported in within {WORKER_ONLINE_SECONDS} s",
            ("worker",),
        ),
        "isolated": _gauge(
            "ansideck_worker_isolated",
            "1 if its runs execute as per-slot users, 0 if not, -1 if not reported",
            ("worker",),
        ),
        "seen": _gauge(
            "ansideck_worker_last_seen_timestamp_seconds",
            "When the worker last reported in",
            ("worker",),
        ),
    }
    for worker_id, slots, isolated, seen, online, busy in workers[:MAX_WORKER_SERIES]:
        per_worker["slots"].add_metric([worker_id], slots)
        per_worker["busy"].add_metric([worker_id], busy)
        per_worker["online"].add_metric([worker_id], 1 if online else 0)
        per_worker["isolated"].add_metric([worker_id], -1 if isolated is None else int(isolated))
        per_worker["seen"].add_metric([worker_id], float(seen))
    slots = _gauge("ansideck_slots", "Run slots of the online workers", ("state",))
    slots.add_metric(["total"], sum(w[1] for w in workers if w[4]))
    slots.add_metric(["busy"], sum(w[5] for w in workers if w[4]))

    galaxy = dict(
        rows(
            "SELECT status, count(*) FROM galaxy_installs "
            "WHERE status IN ('queued', 'running') GROUP BY 1"
        )
    )
    installs = _gauge("ansideck_galaxy_installs", "Galaxy installs queued or running", ("status",))
    for install_status in ("queued", "running"):
        installs.add_metric([install_status], galaxy.get(install_status, 0))

    pending = dict(
        rows(
            "SELECT status, count(*) FROM notification_deliveries "
            "WHERE status IN ('pending', 'sending') GROUP BY 1"
        )
    )
    outbox = _gauge("ansideck_notification_outbox", "Notifications waiting to be sent", ("status",))
    for delivery_status in ("pending", "sending"):
        outbox.add_metric([delivery_status], pending.get(delivery_status, 0))
    outbox_age = _gauge(
        "ansideck_notification_outbox_oldest_age_seconds",
        "Age of the oldest notification not sent yet (0: none)",
    )
    outbox_age.add_metric(
        [],
        float(
            one(
                "SELECT coalesce(extract(epoch FROM now() - min(created_at)), 0) "
                "FROM notification_deliveries WHERE status IN ('pending', 'sending')"
            )
        ),
    )

    raised = dict(
        rows("SELECT split_part(key, ':', 1), count(*) FROM notification_alerts GROUP BY 1")
    )
    alerts = _gauge(
        "ansideck_ops_alerts",
        "Ops alerts raised now (workers offline or not isolated, the queue stuck)",
        ("kind",),
    )
    for kind in _ALERT_KINDS:
        alerts.add_metric([kind], raised.get(kind, 0))

    return [
        info,
        runs,
        cancelling,
        oldest,
        by_state,
        *per_worker.values(),
        slots,
        installs,
        outbox,
        outbox_age,
        alerts,
    ]


class DatabaseCollector(Collector):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached: list[GaugeMetricFamily] = []
        self._cached_at = float("-inf")
        self._up = 0
        self._took = 0.0
        self._warned_at = float("-inf")

    def _refresh(self) -> None:
        started = time.monotonic()
        try:
            db = get_sessionmaker()()
            try:
                self._cached = _read(db)
            finally:
                db.rollback()
                db.close()
            self._up = 1
        except Exception:  # noqa: BLE001 - the in-process metrics are still worth serving
            self._cached, self._up = [], 0
            if started - self._warned_at >= _WARN_EVERY_SECONDS:
                self._warned_at = started
                logger.exception("metrics: could not read the database")
        self._took = time.monotonic() - started
        self._cached_at = time.monotonic()

    def collect(self) -> Iterator[GaugeMetricFamily]:
        with self._lock:
            if time.monotonic() - self._cached_at >= CACHE_SECONDS:
                self._refresh()
            cached, up, took = self._cached, self._up, self._took
        db_up = _gauge("ansideck_db_up", "1 if the last database read for these metrics worked")
        db_up.add_metric([], up)
        duration = _gauge(
            "ansideck_metrics_collect_duration_seconds", "Time the last database read took"
        )
        duration.add_metric([], took)
        yield db_up
        yield duration
        yield from cached

    def invalidate(self) -> None:
        """Forget the cached read (tests)."""
        with self._lock:
            self._cached_at = float("-inf")


database_collector = DatabaseCollector()
REGISTRY.register(database_collector)


class MetricsAuthMiddleware:
    """Pure ASGI: the bearer token is checked before any routing."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = (scope.get("client") or ("", 0))[0]

        async def reject(code: int, detail: str) -> None:
            await JSONResponse({"detail": detail}, code)(scope, receive, send)

        if metrics_ip_throttle.blocked(ip):
            await reject(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts")
            return
        expected = f"Bearer {get_settings().metrics_token}".encode()
        sent = dict(scope["headers"]).get(b"authorization", b"")
        if not get_settings().metrics_token or not hmac.compare_digest(sent, expected):
            metrics_ip_throttle.record_failure(ip)
            await asyncio.to_thread(_audit_auth_failure, ip)
            await reject(status.HTTP_401_UNAUTHORIZED, "Invalid metrics token")
            return
        await self.app(scope, receive, send)


def _audit_auth_failure(ip: str) -> None:
    db = get_sessionmaker()()
    try:
        audit.record(db, "metrics.auth_failed", outcome="failure", target_type="metrics", ip=ip)
    finally:
        db.close()


metrics_app = FastAPI(title="AnsiDeck metrics", docs_url=None, redoc_url=None, openapi_url=None)


@metrics_app.get("/metrics")
async def metrics() -> Response:
    body = await asyncio.to_thread(generate_latest, REGISTRY)
    return Response(body, media_type=CONTENT_TYPE_LATEST)


metrics_app.add_middleware(MetricsAuthMiddleware)
