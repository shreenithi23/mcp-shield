"""SQLAlchemy database models for MCP Shield."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.types import JSON

from mcp_shield.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """User account authenticated via upstream IdP (Google, Entra, Mock)."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    provider = Column(String(64), nullable=False, default="mock")
    provider_sub = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class Client(Base):
    """Registered OAuth 2.1 client (e.g. AI agent or developer tool)."""
    __tablename__ = "clients"

    client_id = Column(String(64), primary_key=True)
    client_secret = Column(String(255), nullable=True)  # Null for public clients with PKCE
    client_name = Column(String(255), nullable=False)
    redirect_uris = Column(JSON, nullable=False, default=list)
    grant_types = Column(JSON, nullable=False, default=lambda: ["authorization_code"])
    response_types = Column(JSON, nullable=False, default=lambda: ["code"])
    token_endpoint_auth_method = Column(String(64), nullable=False, default="none")
    scope = Column(String(255), nullable=True, default="mcp")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class OAuthSession(Base):
    """OAuth 2.1 Authorization Code session and PKCE challenge tracking."""
    __tablename__ = "oauth_sessions"

    session_id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    client_id = Column(String(64), ForeignKey("clients.client_id"), nullable=False)
    auth_code = Column(String(128), unique=True, nullable=True, index=True)
    code_challenge = Column(String(128), nullable=False)
    code_challenge_method = Column(String(32), nullable=False, default="S256")
    redirect_uri = Column(String(512), nullable=False)
    scope = Column(String(255), nullable=False, default="mcp")
    resource = Column(String(512), nullable=False)  # RFC 8707 Resource Indicator
    task_id = Column(String(1024), nullable=False)  # User's original instruction
    state = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)


class IssuedToken(Base):
    """Durable audit record of issued access tokens."""
    __tablename__ = "issued_tokens"

    jti = Column(String(64), primary_key=True)
    client_id = Column(String(64), ForeignKey("clients.client_id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    token_type = Column(String(32), default="Bearer", nullable=False)
    audience = Column(String(512), nullable=False)  # Bound MCP server URI
    task_id = Column(String(1024), nullable=False)  # Bound user task
    act = Column(JSON, nullable=True)               # Actor delegation claim
    scope = Column(String(255), nullable=False)
    issued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


Index("idx_issued_tokens_client_user", IssuedToken.client_id, IssuedToken.user_id)
Index("idx_issued_tokens_audience", IssuedToken.audience)
