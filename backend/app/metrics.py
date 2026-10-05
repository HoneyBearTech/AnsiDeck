"""Prometheus instruments counted inside the API process (app.metrics_api serves them, with
the gauges it reads from the database at scrape time).

Labels stay low-cardinality and free of secrets: project ids (never names; a rename would
start a new series), statuses, route templates (never raw paths), worker ids, audit actions.
Never a user name, playbook, host, run id or anything from a run's output.

The API is one process (`fastapi run` without --workers), so plain in-memory counters are
complete; they start from zero on a restart, which Prometheus' rate() handles.
"""

import logging
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    gc_collector,
    platform_collector,
    process_collector,
)
from prometheus_client.metrics import disable_created_metrics
from sqlalchemy import event
from sqlalchemy.orm import Session, SessionTransaction

logger = logging.getLogger(__name__)

# `_created` series double every counter's output and nothing here reads them.
disable_created_metrics()

REGISTRY = CollectorRegistry()
process_collector.ProcessCollector(registry=REGISTRY)
platform_collector.PlatformCollector(registry=REGISTRY)
gc_collector.GCCollector(registry=REGISTRY)

try:
    _VERSION = version("ansideck-backend")
except PackageNotFoundError:  # pragma: no cover - only outside an installed project
    _VERSION = "unknown"

BUILD_INFO = Gauge(
    "ansideck_build_info", "The running AnsiDeck version (always 1)", ["version"], registry=REGISTRY
)
BUILD_INFO.labels(_VERSION).set(1)

HTTP_REQUESTS = Counter(
    "ansideck_http_requests",
    "HTTP requests answered, by server (public API or internal worker API) and route template",
    ["server", "method", "route", "status"],
    registry=REGISTRY,
)
HTTP_DURATION = Histogram(
    "ansideck_http_request_duration_seconds",
    "Time to answer an HTTP request (worker claims long-poll for up to 25 s)",
    ["server", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    registry=REGISTRY,
)
RUNS_QUEUED = Counter(
    "ansideck_runs_queued",
    "Runs triggered, by who triggered them (user or api_key)",
    ["project_id", "trigger"],
    registry=REGISTRY,
)
RUNS_FINISHED = Counter(
    "ansideck_runs_finished",
    "Runs that ended, by final status",
    ["project_id", "status"],
    registry=REGISTRY,
)
RUN_DURATION = Histogram(
    "ansideck_run_duration_seconds",
    "From ansible's start to the run's end (runs that never started are not counted)",
    ["project_id"],
    buckets=(5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400, 43200, 86400),
    registry=REGISTRY,
)
QUEUE_WAIT = Histogram(
    "ansideck_run_queue_wait_seconds",
    "How long a run waited in the queue before a worker claimed it",
    buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
    registry=REGISTRY,
)
AUDIT_EVENTS = Counter(
    "ansideck_audit_events",
    "Audit events recorded, by action and outcome",
    ["action", "outcome"],
    registry=REGISTRY,
)
LOGIN_LOCKOUTS = Counter(
    "ansideck_login_lockouts",
    "Failed sign-ins (password, second factor, re-authentication) that locked out a name or "
    "address",
    registry=REGISTRY,
)
NOTIFICATION_DELIVERIES = Counter(
    "ansideck_notification_deliveries",
    "Notification send attempts, by channel kind and outcome (sent, retry, failed)",
    ["kind", "outcome"],
    registry=REGISTRY,
)

# A labelled counter only exists from its first increment, and Prometheus' increase() can't
# see that first step: start the ones security dashboards and alerts watch at zero.
for _action, _outcome in (
    ("auth.login", "failure"),
    ("apikey.auth", "failure"),
    ("worker.auth_failed", "failure"),
    ("metrics.auth_failed", "failure"),
    ("permission.denied", "denied"),
):
    AUDIT_EVENTS.labels(_action, _outcome)

GIT_SYNCS = Counter(
    "ansideck_git_syncs",
    "Git source syncs, by outcome (ok: a new commit, unchanged, failed, busy)",
    ["outcome"],
    registry=REGISTRY,
)
GIT_SYNC_DURATION = Histogram(
    "ansideck_git_sync_duration_seconds",
    "Time one git source sync took",
    buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
    registry=REGISTRY,
)
for _outcome in ("ok", "unchanged", "failed"):
    GIT_SYNCS.labels(_outcome)
INVENTORY_REFRESHES = Counter(
    "ansideck_inventory_refreshes",
    "Inventory refreshes (dynamic sources), by how they ended",
    ["outcome"],
    registry=REGISTRY,
)
INVENTORY_REFRESH_DURATION = Histogram(
    "ansideck_inventory_refresh_duration_seconds",
    "Time one inventory refresh took, from start to snapshot",
    buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900),
    registry=REGISTRY,
)
for _outcome in ("success", "failed", "timed_out"):
    INVENTORY_REFRESHES.labels(_outcome)
LINT_JOBS = Counter(
    "ansideck_lint_jobs",
    "Playbook checks (ansible-lint), by how they ended",
    ["outcome"],
    registry=REGISTRY,
)
LINT_DURATION = Histogram(
    "ansideck_lint_duration_seconds",
    "Time one playbook check took, from its start in a worker to its result",
    buckets=(1, 2.5, 5, 10, 20, 30, 60, 120, 300),
    registry=REGISTRY,
)
for _outcome in ("success", "failed", "timed_out", "cancelled"):
    LINT_JOBS.labels(_outcome)
SECRET_STORE_READS = Counter(
    "ansideck_secret_store_reads",
    "Reads from the secret store, by outcome (ok or the error kind)",
    ["outcome"],
    registry=REGISTRY,
)
SECRET_STORE_UP = Gauge(
    "ansideck_secret_store_up",
    "1 if the last secret store check worked (only reported when a store is configured)",
    registry=REGISTRY,
)
for _outcome in ("ok", "unreachable", "denied", "not_found", "auth_failed", "sealed"):
    SECRET_STORE_READS.labels(_outcome)

_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_ACTION = re.compile(r"^[a-z_]{1,30}\.[a-z_]{1,40}$")
_OUTCOMES = frozenset({"success", "failure", "denied"})
_PENDING = "ansideck_metrics_pending"


# --- Counted once the transaction that did it commits -----------------------------------


def after_commit(db: Session, observe: Callable[[], None]) -> None:
    """Runs `observe` once the session's current transaction commits (dropped if it rolls
    back), so a counter never counts what didn't happen."""
    db.info.setdefault(_PENDING, []).append(observe)


@event.listens_for(Session, "after_commit")
def _observe_committed(session: Session) -> None:
    for observe in session.info.pop(_PENDING, []):
        try:
            observe()
        except Exception:  # metrics must never break a request
            logger.exception("could not record a metric")


@event.listens_for(Session, "after_transaction_end")
def _forget_uncommitted(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:  # the outermost transaction (savepoints don't count)
        session.info.pop(_PENDING, None)


def project_series(project_ids) -> None:
    """Starts every project's run counters at zero (called with the projects at each scrape),
    so the first run of a project or status isn't lost to increase()."""
    for project_id in map(str, project_ids):
        for status in ("success", "failed", "cancelled", "timed_out"):
            RUNS_FINISHED.labels(project_id, status)
        for trigger in ("user", "api_key"):
            RUNS_QUEUED.labels(project_id, trigger)
        RUN_DURATION.labels(project_id)


def run_queued(project_id: int, via_api_key: bool) -> None:
    RUNS_QUEUED.labels(str(project_id), "api_key" if via_api_key else "user").inc()


def run_finished(db: Session, project_id: int, status: str, started_at: datetime | None) -> None:
    """Called where a run ends (app.queue.fail_run, the internal complete endpoint), before
    their commit. `started_at` is None for runs that never launched ansible."""
    started = isinstance(started_at, datetime)
    duration = (datetime.now(UTC) - started_at).total_seconds() if started else None
    labels = str(project_id), status

    def observe() -> None:
        RUNS_FINISHED.labels(*labels).inc()
        if duration is not None:
            RUN_DURATION.labels(labels[0]).observe(max(duration, 0.0))

    after_commit(db, observe)


def run_claimed(wait_seconds: float) -> None:
    QUEUE_WAIT.observe(max(wait_seconds, 0.0))


def secret_store_read(outcome: str) -> None:
    SECRET_STORE_READS.labels(outcome[:20]).inc()


def secret_store_up(up: bool) -> None:
    SECRET_STORE_UP.set(1 if up else 0)


def inventory_refresh_finished(outcome: str, seconds: float | None) -> None:
    INVENTORY_REFRESHES.labels(outcome[:20]).inc()
    if seconds is not None and outcome == "success":
        INVENTORY_REFRESH_DURATION.observe(seconds)


def lint_finished(outcome: str, seconds: float | None) -> None:
    LINT_JOBS.labels(outcome[:20]).inc()
    if seconds is not None and outcome == "success":
        LINT_DURATION.observe(seconds)


def git_sync_finished(outcome: str, seconds: float) -> None:
    GIT_SYNCS.labels(outcome).inc()
    if outcome != "busy":
        GIT_SYNC_DURATION.observe(seconds)


def audit_recorded(action: str, outcome: str, locked_out: bool) -> None:
    AUDIT_EVENTS.labels(
        action if _ACTION.match(action) else "other",
        outcome if outcome in _OUTCOMES else "other",
    ).inc()
    if locked_out:
        LOGIN_LOCKOUTS.inc()


def notification_attempted(kind: str, status: str) -> None:
    """`status` is the delivery's status after the attempt: sent, pending (a retry is due)
    or failed."""
    outcome = {"sent": "sent", "pending": "retry", "failed": "failed"}.get(status)
    if outcome is not None:
        NOTIFICATION_DELIVERIES.labels(kind[:20], outcome).inc()


# --- HTTP -------------------------------------------------------------------------------


def route_template(scope: dict) -> str:
    """The matched route's path template ("/api/runs/{run_id}"), never the raw path: raw
    paths would put ids (and whatever a scanner sends) into labels. FastAPI 0.141 keeps the
    full template of a route on an included router only in this private scope entry; the
    route itself knows just its part after the prefix (tests pin both)."""
    context = (scope.get("fastapi") or {}).get("effective_route_context")
    template = getattr(context, "path_format", None)
    if not template:
        route = scope.get("route")
        template = getattr(route, "path_format", None)
    return template or "unmatched"


class HTTPMetricsMiddleware:
    """Pure ASGI and outermost, so requests other middleware refuse (Origin check, worker
    token) are counted too. WebSockets (live run output) are not requests and are skipped."""

    def __init__(self, app, server: str) -> None:
        self.app = app
        self.server = server

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status_code = 500

        async def send_and_note(message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_note)
        finally:
            method = scope["method"] if scope["method"] in _METHODS else "other"
            route = route_template(scope)
            HTTP_REQUESTS.labels(self.server, method, route, str(status_code)).inc()
            HTTP_DURATION.labels(self.server, method, route).observe(time.perf_counter() - started)
