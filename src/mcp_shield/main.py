"""Main FastAPI Application for MCP Shield."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mcp_shield.config import settings
from mcp_shield.database import init_db
from mcp_shield.logging import get_access_logger
from mcp_shield.middleware import AccessLoggingMiddleware
from mcp_shield.ciba.router import router as ciba_router
from mcp_shield.oauth.authorize import router as authorize_router
from mcp_shield.oauth.dcr import router as dcr_router
from mcp_shield.oauth.introspect import router as introspect_router
from mcp_shield.oauth.jwks import router as jwks_router
from mcp_shield.oauth.metadata import router as metadata_router
from mcp_shield.oauth.resource_demo import router as resource_demo_router
from mcp_shield.oauth.revoke import router as revoke_router
from mcp_shield.oauth.token import router as token_router
from mcp_shield.proxy.router import router as proxy_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables and logger on startup
    await init_db()
    get_access_logger()
    yield


app = FastAPI(
    title="MCP Shield",
    description="Zero-Trust Gateway between AI Agents and MCP Tool Servers",
    version="0.1.0",
    lifespan=lifespan,
)

# Standard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mandatory Access Logging Middleware for all requests
app.add_middleware(AccessLoggingMiddleware)

from mcp_shield.console.router import router as console_router
from mcp_shield.console.ui import ui_router as console_ui_router

# Mount all endpoints
app.include_router(metadata_router)
app.include_router(jwks_router)
app.include_router(dcr_router)
app.include_router(authorize_router)
app.include_router(token_router)
app.include_router(revoke_router)
app.include_router(introspect_router)
app.include_router(resource_demo_router)
app.include_router(proxy_router)
app.include_router(ciba_router)
app.include_router(console_router)
app.include_router(console_ui_router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check."""
    return {"status": "healthy", "service": "mcp-shield", "phase": 1}
