import os
import tempfile
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Load local .env if present (e.g. for GITHUB_PAT)
load_dotenv()

# Set test environment variables before importing app modules
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ACCESS_LOG_PATH"] = tempfile.mktemp(prefix="access_", suffix=".log")
os.environ["REDIS_ENABLED"] = "false"

from mcp_shield.config import settings
from mcp_shield.database import Base, get_db
from mcp_shield.logging import get_access_logger, reset_access_logger_for_test
from mcp_shield.main import app

# Shared test engine
test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    future=True,
)
TestingSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(autouse=True)
def setup_temp_log_file(tmp_path):
    log_file = tmp_path / "access.log"
    settings.ACCESS_LOG_PATH = str(log_file)
    reset_access_logger_for_test(str(log_file))
    yield str(log_file)


@pytest_asyncio.fixture
async def db_session():
    async with TestingSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as ac:
        yield ac
    app.dependency_overrides.clear()
