import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator, Iterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg.errors import NumericValueOutOfRange
from sqlalchemy.exc import DataError

from app import audit
from app.bootstrap import refuse_to_start_over_legacy_data, seed_fresh_install
from app.config import get_settings
from app.db import get_sessionmaker, init_db
from app.hardening import OriginCheckMiddleware
from app.internal_api import internal_app
from app.process_hardening import disable_process_inspection
from app.reaper import INTERVAL_SECONDS, reap_once
from app.routers import (
    api_keys,
    auth,
    credentials,
    galaxy,
    health,
    inventories,
    playbooks,
    projects,
    runs,
    sso,
    users,
    vault,
    vault_passwords,
)
from app.routers import (
    audit as audit_router,
)
from app.storage import galaxy_collections_dir, galaxy_roles_dir

logger = logging.getLogger(__name__)
settings = get_settings()


class _EmbeddedServer(uvicorn.Server):
    """Serves the internal worker API from the API's own event loop. Signals stay with the
    main server (which then ends the lifespan, and with it this server)."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


async def _reap_forever() -> None:
    while True:
        try:
            await asyncio.to_thread(reap_once)
        except Exception:  # noqa: BLE001 - the next pass tries again
            logger.exception("reaper pass failed")
        await asyncio.sleep(INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    disable_process_inspection()
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
    internal = serving = None
    if settings.internal_api_enabled:
        internal = _EmbeddedServer(
            uvicorn.Config(
                internal_app,
                host=settings.internal_api_host,
                port=settings.internal_api_port,
                lifespan="off",
                log_level="warning",
            )
        )
        serving = asyncio.create_task(internal.serve())
    try:
        yield
    finally:
        reaper.cancel()
        if internal is not None:
            internal.should_exit = True  # graceful: in-flight worker calls finish
        await asyncio.gather(reaper, *([serving] if serving else []), return_exceptions=True)


app = FastAPI(title="AnsiDeck API", version="0.1.0", lifespan=lifespan)


@app.exception_handler(DataError)
async def _integer_out_of_range(request: Request, exc: DataError) -> JSONResponse:
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

app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(sso.router, prefix="/api/auth", tags=["auth"])
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["playbooks"])
app.include_router(inventories.router, prefix="/api/inventories", tags=["inventories"])
app.include_router(credentials.router, prefix="/api/credentials", tags=["credentials"])
app.include_router(vault_passwords.router, prefix="/api/vault-passwords", tags=["vault-passwords"])
app.include_router(vault.router, prefix="/api/vault", tags=["vault"])
app.include_router(galaxy.router, prefix="/api/galaxy", tags=["galaxy"])
app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])
app.include_router(api_keys.router, prefix="/api/projects/{project_id}/api-keys", tags=["api-keys"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(audit_router.router, prefix="/api/audit", tags=["audit"])
