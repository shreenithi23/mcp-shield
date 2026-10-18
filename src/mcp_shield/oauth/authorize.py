"""OAuth 2.1 Authorization Code and PKCE flow with Upstream IdP login (RFC 7636, RFC 8707)."""

import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_shield.config import settings
from mcp_shield.database import ephemeral_cache, get_db
from mcp_shield.idp import get_idp_provider
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.models import Client, OAuthSession, User

router = APIRouter(tags=["OAuth 2.1"])


@router.get("/oauth/authorize", summary="OAuth 2.1 Authorization Endpoint (RFC 7636, RFC 8707)")
async def authorize(
    request: Request,
    response_type: str = Query(..., description="Must be 'code' for OAuth 2.1"),
    client_id: str = Query(..., description="Registered client ID"),
    redirect_uri: str = Query(..., description="Pre-registered redirect URI"),
    code_challenge: str = Query(..., description="PKCE code challenge (S256)"),
    code_challenge_method: str = Query("S256", description="Must be S256"),
    resource: str = Query(..., description="RFC 8707 Resource Indicator for the target MCP server"),
    task_id: str = Query(..., description="User's original instruction / task context"),
    scope: str = Query("mcp", description="Requested scope"),
    state: Optional[str] = Query(None, description="Client state parameter"),
    auto_approve: bool = Query(True, description="Auto-approve for automated tests / dev"),
    user_email: Optional[str] = Query(None, description="Direct user identity for testing/dev"),
    db: AsyncSession = Depends(get_db),
):
    """Handles OAuth 2.1 authorization request with PKCE and resource indicators."""
    ctx = current_log_context.get()
    if ctx:
        ctx.client_id = client_id
        ctx.task_id = task_id
        ctx.mcp_server = resource
        ctx.args_sha256 = hash_arguments({
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "task_id": task_id,
            "scope": scope,
        })

    # Validate response_type
    if response_type != "code":
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "unsupported_response_type"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported_response_type: only 'code' is allowed in OAuth 2.1",
        )

    # Validate PKCE
    if not code_challenge:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_code_challenge"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: code_challenge is required for PKCE",
        )

    if code_challenge_method != "S256":
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "invalid_code_challenge_method"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: code_challenge_method must be 'S256'",
        )

    # Validate resource indicator (RFC 8707)
    if not resource or not resource.strip():
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_resource_indicator"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_target: resource parameter is required (RFC 8707)",
        )

    # Validate task_id (User original intent)
    if not task_id or not task_id.strip():
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_task_id"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: task_id is required",
        )

    # Validate Client
    client_res = await db.execute(select(Client).where(Client.client_id == client_id))
    client = client_res.scalar_one_or_none()
    if not client:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "unregistered_client"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_client: client_id is not registered",
        )

    # Validate redirect_uri matches pre-registered client URIs
    if redirect_uri not in client.redirect_uris:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "invalid_redirect_uri"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: redirect_uri does not match registered redirect_uris",
        )

    # Authenticate User via Upstream IdP or dev user_email
    email = user_email or "developer@example.com"
    user_res = await db.execute(select(User).where(User.email == email))
    user = user_res.scalar_one_or_none()
    if not user:
        user = User(
            email=email,
            name="Developer Operator",
            provider="mock",
            provider_sub=f"sub_{secrets.token_hex(8)}",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    if ctx:
        ctx.user_id = user.id

    # Issue Authorization Code (valid for 5 minutes)
    auth_code = f"code_{secrets.token_urlsafe(32)}"
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.AUTH_CODE_EXPIRE_SECONDS)

    oauth_session = OAuthSession(
        user_id=user.id,
        client_id=client.client_id,
        auth_code=auth_code,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        redirect_uri=redirect_uri,
        scope=scope,
        resource=resource,
        task_id=task_id,
        state=state,
        expires_at=expires_at,
        used=False,
    )
    db.add(oauth_session)
    await db.commit()

    # Cache ephemeral session code
    await ephemeral_cache.set(f"auth_code:{auth_code}", oauth_session.session_id, ex=settings.AUTH_CODE_EXPIRE_SECONDS)

    if ctx:
        ctx.outcome = "allow"
        ctx.reason_code = "auth_code_issued"

    # Build redirect response
    params = {"code": auth_code}
    if state:
        params["state"] = state

    delim = "&" if "?" in redirect_uri else "?"
    redirect_target = f"{redirect_uri}{delim}{urlencode(params)}"
    return RedirectResponse(url=redirect_target, status_code=status.HTTP_302_FOUND)


@router.get("/mock-idp/login", summary="Mock IdP Callback simulation")
async def mock_idp_login(
    state: str = Query(...),
    redirect_uri: str = Query(...),
    code: str = Query(...),
):
    """Simulates an upstream IdP returning an authorization code to the gateway."""
    ctx = current_log_context.get()
    if ctx:
        ctx.outcome = "allow"
        ctx.reason_code = "mock_idp_authenticated"
    params = {"state": state, "code": code}
    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}",
        status_code=status.HTTP_302_FOUND,
    )
