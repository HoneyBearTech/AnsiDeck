import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import audit
from app.bootstrap import seed_admin_user
from app.config import get_settings
from app.db import get_sessionmaker, init_db
from app.hardening import OriginCheckMiddleware, disable_process_inspection
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
from app.run_engine import set_event_loop

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    disable_process_inspection()
    init_db()
    set_event_loop(asyncio.get_running_loop())
    session = get_sessionmaker()()
    try:
        seed_admin_user(session)
        audit.prune(session, settings.audit_retention_days)
    finally:
        session.close()
    yield


app = FastAPI(title="AnsiDeck API", version="0.1.0", lifespan=lifespan)


@app.exception_handler(OverflowError)
async def _integer_out_of_range(request: Request, exc: OverflowError) -> JSONResponse:
    """An id beyond SQLite's 64-bit INTEGER range cannot match any row, so answer it like any
    other missing resource instead of a 500. Any other OverflowError is a real bug: re-raise."""
    if "SQLite INTEGER" not in str(exc):
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
