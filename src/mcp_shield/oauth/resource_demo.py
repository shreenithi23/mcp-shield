"""Protected Resource implementation showcasing RFC 9728 discovery and RFC 8707 audience checks."""

from typing import Optional
from fastapi import APIRouter, Header, HTTPException, Query, Response, status
from mcp_shield.config import settings
from mcp_shield.crypto import crypto_manager
from mcp_shield.database import ephemeral_cache
from mcp_shield.logging import current_log_context

router = APIRouter(prefix="/mcp", tags=["Protected Resource PEP"])


@router.get("/resource-test", summary="Test protected resource requiring audience-bound Bearer token")
async def protected_resource_test(
    authorization: Optional[str] = Header(None),
    resource_id: str = Query(..., description="Target MCP server resource identifier"),
):
    """Protected resource endpoint enforcing RFC 9728 discovery and RFC 8707 single-resource audience binding."""
    ctx = current_log_context.get()
    metadata_url = f"{settings.BASE_URL}/.well-known/oauth-protected-resource"

    if ctx:
        ctx.mcp_server = resource_id

    # 1. Discovery Flow: 401 + WWW-Authenticate with resource_metadata pointer (RFC 9728)
    if not authorization or not authorization.startswith("Bearer "):
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_bearer_token"
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}", error="unauthorized"'
            },
            content='{"error": "unauthorized", "message": "Bearer token required"}',
            media_type="application/json",
        )

    raw_token = authorization.split("Bearer ", 1)[1].strip()

    # 2. Token Verification & Audience check (RFC 8707)
    try:
        claims = crypto_manager.verify_access_token(raw_token, expected_audience=resource_id)
        jti = claims.get("jti")
        if ctx and jti:
            ctx.token_jti = jti
            ctx.user_id = claims.get("sub")
            ctx.client_id = claims.get("client_id")
            ctx.task_id = claims.get("task_id")

        # Check revocation
        if jti and await ephemeral_cache.is_jti_revoked(jti):
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "token_revoked"
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}", error="invalid_token", error_description="token is revoked"'
                },
                content='{"error": "invalid_token", "message": "Token has been revoked"}',
                media_type="application/json",
            )

        if ctx:
            ctx.outcome = "allow"
            ctx.reason_code = "authorized"

        return {
            "status": "authorized",
            "resource": resource_id,
            "sub": claims.get("sub"),
            "client_id": claims.get("client_id"),
            "task_id": claims.get("task_id"),
            "claims": claims,
        }

    except ValueError as exc:
        msg = str(exc)
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "audience_mismatch" if "Audience mismatch" in msg else "invalid_token"

        # Audience mismatch or invalid token
        http_code = status.HTTP_403_FORBIDDEN if "Audience mismatch" in msg else status.HTTP_401_UNAUTHORIZED
        return Response(
            status_code=http_code,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}", error="invalid_token", error_description="{msg}"'
            },
            content=f'{{"error": "invalid_token", "message": "{msg}"}}',
            media_type="application/json",
        )
    except Exception as exc:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = f"token_validation_error_{type(exc).__name__}"
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}", error="invalid_token", error_description="Invalid or expired token"'
            },
            content='{"error": "invalid_token", "message": "Token verification failed"}',
            media_type="application/json",
        )
