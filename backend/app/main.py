import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg.errors import NumericValueOutOfRange
from sqlalchemy.exc import DataError

from app import audit, metrics, secret_store
from app.bootstrap import refuse_to_start_over_legacy_data, seed_fresh_install
from app.config import get_settings
from app.db import get_sessionmaker, init_db
from app.git_sync import LOOP_SECONDS, SYNC_TOPIC, due_sources, sync_source
from app.hardening import OriginCheckMiddleware
from app.internal_api import internal_app
from app.metrics_api import metrics_app
from app.notifications.dispatch import dispatch_forever
from app.notifications.ops import secret_store_failed, secret_store_ok
from app.notify import notifier
from app.process_hardening import disable_process_inspection
from app.reaper import INTERVAL_SECONDS, reap_once
from app.routers import (
    api_keys,
    auth,
    credentials,
    galaxy,
    git_sources,
    health,
    inventories,
    inventory_sources,
    lint,
    notifications,
    playbooks,
    projects,
    run_templates,
    runs,
    sso,
    users,
    vault,
    vault_passwords,
    workers,
)
from app.routers import (
    audit as audit_router,
)
from app.routers import (
    secret_store as secret_store_router,
)
from app.storage import galaxy_collections_dir, galaxy_roles_dir

logger = logging.getLogger(__name__)
settings = get_settings()
SECRET_STORE_PROBE_SECONDS = 60


class _EmbeddedServer(uvicorn.Server):
    """Serves the internal worker API from the API's own event loop. Signals stay with the
    main server (which then ends the lifespan, and with it this server)."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _embedded(asgi_app: FastAPI, host: str, port: int) -> _EmbeddedServer:
    return _EmbeddedServer(
        uvicorn.Config(asgi_app, host=host, port=port, lifespan="off", log_level="warning")
    )


def _due_sources() -> list[int]:
    db = get_sessionmaker()()
    try:
        return due_sources(db)
    finally:
        db.close()


async def _git_sync_forever() -> None:
    """Syncs git sources when due or requested, a few at a time, each in a thread."""
    loop = asyncio.get_running_loop()
    limit = settings.git_sync_concurrency
    executor = ThreadPoolExecutor(max_workers=limit, thread_name_prefix="git-sync")
    running: set[int] = set()

    def finished(source_id: int) -> None:
        running.discard(source_id)
        notifier.notify(SYNC_TOPIC)  # a slot is free: look again

    try:
        with notifier.listen(SYNC_TOPIC) as listener:
            while True:
                try:
                    for source_id in await asyncio.to_thread(_due_sources):
                        if source_id in running or len(running) >= limit:
                            continue
                        running.add(source_id)
                        future = loop.run_in_executor(executor, sync_source, source_id)
                        future.add_done_callback(lambda _f, sid=source_id: finished(sid))
                except Exception:  # the next round tries again
                    logger.exception("git sync round failed")
                await listener.wait(LOOP_SECONDS)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _probe_secret_store() -> None:
    """Checks the secret store and raises or clears its ops alert."""
    result = secret_store.probe()
    label = settings.secrets_store_label
    db = get_sessionmaker()()
    try:
        if result["ok"]:
            secret_store_ok(db, label)
        elif result["error_kind"] in secret_store.OUTAGE_KINDS:
            secret_store_failed(db, result["error_kind"], label)
        db.commit()
    finally:
        db.close()


async def _secret_store_probe_forever() -> None:
    if not settings.secrets_store_enabled:
        return
    while True:
        try:
            await asyncio.to_thread(_probe_secret_store)
        except Exception:  # the next probe tries again
            logger.exception("secret store probe failed")
        await asyncio.sleep(SECRET_STORE_PROBE_SECONDS)


async def _reap_forever() -> None:
    while True:
        try:
            await asyncio.to_thread(reap_once)
        except Exception:  # the next pass tries again
            logger.exception("reaper pass failed")
        await asyncio.sleep(INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    disable_process_inspection()
    if old_keys := len(settings.credential_encryption_keys) - 1:
        logger.warning(
            "CREDENTIAL_ENCRYPTION_KEY lists %d old key(s) after the current one: run "
            "`python -m app.cli reencrypt-secrets`, then remove them",
            old_keys,
        )
    init_db()
    session = get_sessionmaker()()
    try:
        refuse_to_start_over_legacy_data(session)
        seed_fresh_install(session)
        audit.prune(session, settings.audit_retention_days)
    finally:
        session.close()
    # Workers mount these read-only, so they must exist before any worker starts.
    galaxy_collections_dir()
    galaxy_roles_dir()

    reaper = asyncio.create_task(_reap_forever())
    dispatcher = asyncio.create_task(dispatch_forever())
    syncer = asyncio.create_task(_git_sync_forever())
    prober = asyncio.create_task(_secret_store_probe_forever())
    servers: list[_EmbeddedServer] = []
    if settings.internal_api_enabled:
        servers.append(
            _embedded(internal_app, settings.internal_api_host, settings.internal_api_port)
        )
    if settings.metrics_token:
        servers.append(_embedded(metrics_app, settings.metrics_host, settings.metrics_port))
    serving = [asyncio.create_task(server.serve()) for server in servers]
    try:
        yield
    finally:
        reaper.cancel()
        dispatcher.cancel()
        syncer.cancel()
        prober.cancel()
        for server in servers:
            server.should_exit = True  # graceful: in-flight worker calls finish
        await asyncio.gather(reaper, dispatcher, syncer, prober, *serving, return_exceptions=True)


app = FastAPI(title="AnsiDeck API", version=metrics.VERSION, lifespan=lifespan)


@app.exception_handler(DataError)
async def _integer_out_of_range(_request: Request, exc: DataError) -> JSONResponse:
    """An id beyond Postgres' INTEGER range cannot match any row, so answer it like any other
    missing resource instead of a 500. Any other DataError is a real bug: re-raise."""
    if not isinstance(exc.orig, NumericValueOutOfRange):
        raise exc
    return JSONResponse({"detail": "Not found"}, status_code=404)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(OriginCheckMiddleware, allowed_origins=settings.cors_origins)
# Outermost, so requests the Origin check refuses are counted too.
app.add_middleware(metrics.HTTPMetricsMiddleware, server="public")

app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(sso.router, prefix="/api/auth", tags=["auth"])
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["playbooks"])
app.include_router(inventories.router, prefix="/api/inventories", tags=["inventories"])
app.include_router(
    inventory_sources.router, prefix="/api/inventories/{inventory_id}", tags=["inventories"]
)
app.include_router(credentials.router, prefix="/api/credentials", tags=["credentials"])
app.include_router(vault_passwords.router, prefix="/api/vault-passwords", tags=["vault-passwords"])
app.include_router(vault.router, prefix="/api/vault", tags=["vault"])
app.include_router(galaxy.router, prefix="/api/galaxy", tags=["galaxy"])
app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])
app.include_router(run_templates.router, prefix="/api/run-templates", tags=["run-templates"])
app.include_router(lint.router, prefix="/api/lint-jobs", tags=["playbooks"])
app.include_router(api_keys.router, prefix="/api/projects/{project_id}/api-keys", tags=["api-keys"])
app.include_router(
    git_sources.router, prefix="/api/projects/{project_id}/git-sources", tags=["git-sources"]
)
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(audit_router.router, prefix="/api/audit", tags=["audit"])
app.include_router(workers.router, prefix="/api/workers", tags=["workers"])
app.include_router(secret_store_router.router, prefix="/api/secret-store", tags=["secret-store"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(
    notifications.project_router,
    prefix="/api/projects/{project_id}/notifications",
    tags=["notifications"],
)
