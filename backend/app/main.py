from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.bootstrap import seed_admin_user
from app.config import get_settings
from app.db import get_sessionmaker, init_db
from app.routers import auth, credentials, health, inventories, playbooks

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    session = get_sessionmaker()()
    try:
        seed_admin_user(session)
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

app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(playbooks.router, prefix="/api/playbooks", tags=["playbooks"])
app.include_router(inventories.router, prefix="/api/inventories", tags=["inventories"])
app.include_router(credentials.router, prefix="/api/credentials", tags=["credentials"])
