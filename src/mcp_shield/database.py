"""Database connection and session management supporting async PostgreSQL with SQLite fallback."""

import json
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Optional, Set
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from mcp_shield.config import settings

Base = declarative_base()

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        db_url = settings.DATABASE_URL
        if settings.ENVIRONMENT == "test" or settings.DATABASE_URL.startswith("sqlite"):
            db_url = settings.SQLITE_FALLBACK_URL
        _engine = create_async_engine(db_url, echo=False, future=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _sessionmaker


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions with resilient SQLite fallback."""
    global _engine, _sessionmaker
    try:
        session_factory = get_sessionmaker()
        session = session_factory()
    except Exception:
        if settings.USE_SQLITE_FALLBACK and not settings.DATABASE_URL.startswith("sqlite"):
            _engine = create_async_engine(settings.SQLITE_FALLBACK_URL, echo=False, future=True)
            _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
            session = _sessionmaker()
        else:
            raise

    async with session:
        yield session


async def init_db() -> None:
    """Creates all tables if they do not exist, falling back to SQLite if Postgres is offline."""
    global _engine, _sessionmaker
    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception:
        if settings.USE_SQLITE_FALLBACK and not settings.DATABASE_URL.startswith("sqlite"):
            _engine = create_async_engine(settings.SQLITE_FALLBACK_URL, echo=False, future=True)
            _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
            async with _engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        else:
            raise


# Ephemeral storage (Redis with in-memory fallback)
class EphemeralCache:
    """Manages short-lived state (auth codes, revocation list) with in-memory fallback."""

    def __init__(self):
        self._memory_store: Dict[str, str] = {}
        self._revoked_jtis: Set[str] = set()

    async def set(self, key: str, value: str, ex: Optional[int] = None) -> None:
        self._memory_store[key] = value

    async def get(self, key: str) -> Optional[str]:
        return self._memory_store.get(key)

    async def delete(self, key: str) -> None:
        self._memory_store.pop(key, None)

    async def revoke_jti(self, jti: str) -> None:
        self._revoked_jtis.add(jti)

    async def is_jti_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis


ephemeral_cache = EphemeralCache()
