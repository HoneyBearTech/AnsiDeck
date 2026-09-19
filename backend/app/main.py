import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import audit
from app.bootstrap import seed_admin_user
from app.config import get_settings
from app.db import get_sessionmaker, init_db
from app.hardening import OriginCheckMiddleware
from app.routers import (
    audit as audit_router,
)
from app.routers import (
    auth,
    credentials,
    galaxy,
    health,
    inventories,
    playbooks,
    runs,
    users,
    vault,
    vault_passwords,
)
from app.run_engine import set_event_loop

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
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
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["playbooks"])
app.include_router(inventories.router, prefix="/api/inventories", tags=["inventories"])
app.include_router(credentials.router, prefix="/api/credentials", tags=["credentials"])
app.include_router(vault_passwords.router, prefix="/api/vault-passwords", tags=["vault-passwords"])
app.include_router(vault.router, prefix="/api/vault", tags=["vault"])
app.include_router(galaxy.router, prefix="/api/galaxy", tags=["galaxy"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(audit_router.router, prefix="/api/audit", tags=["audit"])
