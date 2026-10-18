"""OAuth 2.1 Token Endpoint supporting PKCE (RFC 7636), Resource Indicators (RFC 8707),
RFC 9449 DPoP cnf.jkt binding, RFC 9396 authorization_details, and RFC 8693 Token Exchange.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_shield.config import settings
from mcp_shield.crypto import crypto_manager, verify_pkce_challenge
from mcp_shield.database import ephemeral_cache, get_db
from mcp_shield.dpop.verifier import dpop_verifier
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.models import IssuedToken, OAuthSession
from mcp_shield.schemas import TokenResponse

router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="OAuth 2.1 Token Endpoint (PKCE, DPoP, Resource Indicators, Token Exchange)",
)
async def issue_token(
    request: Request,
    grant_type: str = Form(...),
    # Standard authorization_code fields
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    resource: Optional[str] = Form(None),
    # RFC 9396 authorization_details
    authorization_details: Optional[str] = Form(None),
    # RFC 8693 Token Exchange fields
    subject_token: Optional[str] = Form(None),
    subject_token_type: Optional[str] = Form(None),
    task_id: Optional[str] = Form(None),
    # DPoP header
    dpop: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Exchanges an authorization code or parent token for an audience-bound RS256 JWT access token."""
    ctx = current_log_context.get()
    now_utc = datetime.now(timezone.utc)

    # Parse authorization_details JSON if provided
    authz_details_obj = None
    if authorization_details:
        try:
            authz_details_obj = json.loads(authorization_details)
        except Exception:
            authz_details_obj = None

    # Handle DPoP verification at token issuance if DPoP header was sent
    dpop_jkt: Optional[str] = None
    if dpop:
        valid_dpop, jkt, dpop_err = await dpop_verifier.verify(
            dpop_header=dpop,
            http_method="POST",
            http_url=str(request.url),
        )
        if not valid_dpop:
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = f"dpop_invalid: {dpop_err}"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid_dpop_proof: {dpop_err}",
            )
        dpop_jkt = jkt
        if ctx:
            ctx.dpop_ok = True

    # -------------------------------------------------------------
    # CASE 1: RFC 8693 Token Exchange (Downscoping per task)
    # -------------------------------------------------------------
    if grant_type == TOKEN_EXCHANGE_GRANT:
        if not subject_token:
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "missing_subject_token"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_request: subject_token is required for token-exchange",
            )

        try:
            parent_claims = crypto_manager.verify_access_token(subject_token)
        except Exception as exc:
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "invalid_subject_token"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid_grant: subject_token invalid or expired ({str(exc)})",
            )

        parent_jti = parent_claims.get("jti")
        if parent_jti and await ephemeral_cache.is_jti_revoked(parent_jti):
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "subject_token_revoked"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant: subject_token has been revoked",
            )

        target_resource = resource or parent_claims.get("aud")
        downscoped_task = task_id or parent_claims.get("task_id", "subtask")
        downscoped_client = client_id or parent_claims.get("client_id")
        user_id = parent_claims.get("sub")

        # Downscoped authorization details
        effective_authz = authz_details_obj or parent_claims.get("authorization_details")

        token_jti = str(uuid.uuid4())
        expires_in = settings.ACCESS_TOKEN_EXPIRE_SECONDS
        expires_at = datetime.fromtimestamp(int(time.time()) + expires_in, tz=timezone.utc)

        act_claim = {"client_id": downscoped_client, "act": parent_claims.get("act")}

        downscoped_token = crypto_manager.sign_access_token(
            sub=user_id,
            client_id=downscoped_client,
            aud=target_resource,
            task_id=downscoped_task,
            act=act_claim,
            scope=parent_claims.get("scope", "mcp"),
            expires_in=expires_in,
            jti=token_jti,
            dpop_jkt=dpop_jkt or parent_claims.get("cnf", {}).get("jkt"),
            authorization_details=effective_authz,
        )

        issued_token = IssuedToken(
            jti=token_jti,
            client_id=downscoped_client,
            user_id=user_id,
            token_type="DPoP" if dpop_jkt else "Bearer",
            audience=target_resource,
            task_id=downscoped_task,
            act=act_claim,
            scope=parent_claims.get("scope", "mcp"),
            issued_at=now_utc,
            expires_at=expires_at,
            revoked=False,
        )
        db.add(issued_token)
        await db.commit()

        if ctx:
            ctx.client_id = downscoped_client
            ctx.user_id = user_id
            ctx.task_id = downscoped_task
            ctx.mcp_server = target_resource
            ctx.token_jti = token_jti
            ctx.outcome = "allow"
            ctx.reason_code = "token_exchanged"

        return TokenResponse(
            access_token=downscoped_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=expires_in,
            scope=parent_claims.get("scope", "mcp"),
            resource=target_resource,
        )

    # -------------------------------------------------------------
    # CASE 2: Standard authorization_code Flow with PKCE
    # -------------------------------------------------------------
    if grant_type != "authorization_code":
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "unsupported_grant_type"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported_grant_type: '{grant_type}' not supported",
        )

    if not code or not redirect_uri or not client_id or not code_verifier:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_parameters"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: missing code, redirect_uri, client_id, or code_verifier",
        )

    if ctx:
        ctx.client_id = client_id
        ctx.args_sha256 = hash_arguments({
            "grant_type": grant_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "has_resource": resource is not None,
        })

    # Lookup session by auth code
    stmt = select(OAuthSession).where(OAuthSession.auth_code == code)
    res = await db.execute(stmt)
    session = res.scalar_one_or_none()

    if not session:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "invalid_code"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: authorization code not found",
        )

    # Check expiration (5 minutes TTL)
    exp = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
    if exp < now_utc:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "code_expired"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: authorization code has expired",
        )

    # Check one-time use
    if session.used:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "code_reused"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: authorization code already used",
        )

    # Verify client ID match
    if session.client_id != client_id:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "client_mismatch"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: client_id mismatch",
        )

    # Verify redirect_uri match
    if session.redirect_uri != redirect_uri:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "redirect_uri_mismatch"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: redirect_uri mismatch",
        )

    # Verify Resource Indicator if provided
    if resource and session.resource != resource:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "resource_mismatch"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_target: resource '{resource}' does not match authorized resource '{session.resource}'",
        )

    # Verify PKCE S256 code_verifier
    if not verify_pkce_challenge(code_verifier, session.code_challenge, session.code_challenge_method):
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "pkce_verification_failed"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: PKCE code_verifier verification failed",
        )

    # Mark authorization code as used (single-use)
    session.used = True
    await db.commit()

    # Generate RS256 JWT access token bound to single resource (RFC 8707)
    token_jti = str(uuid.uuid4())
    expires_in = settings.ACCESS_TOKEN_EXPIRE_SECONDS
    expires_at = datetime.fromtimestamp(int(time.time()) + expires_in, tz=timezone.utc)

    # Default authorization details for GitHub MCP if none explicitly requested
    effective_authz = authz_details_obj
    if not effective_authz and session.resource == "https://api.githubcopilot.com/mcp/":
        effective_authz = [
            {
                "type": "mcp_tool",
                "server": session.resource,
                "tools": ["list_issues", "issue_read"],
                "constraints": {
                    "owner": "shreenithi23",
                    "repo": "mcp-shield-test",
                },
            }
        ]

    act_claim = {"client_id": session.client_id}

    access_token = crypto_manager.sign_access_token(
        sub=session.user_id or "anonymous",
        client_id=session.client_id,
        aud=session.resource,
        task_id=session.task_id,
        act=act_claim,
        scope=session.scope,
        expires_in=expires_in,
        jti=token_jti,
        dpop_jkt=dpop_jkt,
        authorization_details=effective_authz,
    )

    # Store token record in database for audit and revocation
    issued_token = IssuedToken(
        jti=token_jti,
        client_id=session.client_id,
        user_id=session.user_id or "anonymous",
        token_type="DPoP" if dpop_jkt else "Bearer",
        audience=session.resource,
        task_id=session.task_id,
        act=act_claim,
        scope=session.scope,
        issued_at=now_utc,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(issued_token)
    await db.commit()

    # Update access log context with token details (never logging raw token!)
    if ctx:
        ctx.user_id = session.user_id
        ctx.task_id = session.task_id
        ctx.mcp_server = session.resource
        ctx.token_jti = token_jti
        ctx.outcome = "allow"
        ctx.reason_code = "token_issued"

    return TokenResponse(
        access_token=access_token,
        token_type="DPoP" if dpop_jkt else "Bearer",
        expires_in=expires_in,
        scope=session.scope,
        resource=session.resource,
    )
