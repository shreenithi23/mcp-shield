"""RFC 7662 Token Introspection Endpoint."""

from typing import Optional
from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_shield.crypto import crypto_manager
from mcp_shield.database import ephemeral_cache, get_db
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.models import IssuedToken
from mcp_shield.schemas import IntrospectResponse

router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])


@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    summary="RFC 7662 Token Introspection Endpoint",
)
async def introspect_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Returns metadata about an active token, or active: false if invalid, revoked, or expired."""
    ctx = current_log_context.get()
    if ctx:
        ctx.args_sha256 = hash_arguments({"token_sha256": hash_arguments(token)})

    try:
        claims = crypto_manager.verify_access_token(token)
        jti = claims.get("jti")
        if ctx and jti:
            ctx.token_jti = jti

        # Check ephemeral cache for revocation
        if jti and await ephemeral_cache.is_jti_revoked(jti):
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "token_revoked"
            return IntrospectResponse(active=False)

        # Check database for revocation
        if jti:
            stmt = select(IssuedToken).where(IssuedToken.jti == jti)
            res = await db.execute(stmt)
            issued = res.scalar_one_or_none()
            if issued and issued.revoked:
                if ctx:
                    ctx.outcome = "deny"
                    ctx.reason_code = "token_revoked"
                return IntrospectResponse(active=False)

        if ctx:
            ctx.user_id = claims.get("sub")
            ctx.client_id = claims.get("client_id")
            ctx.task_id = claims.get("task_id")
            ctx.mcp_server = claims.get("aud")
            ctx.outcome = "allow"
            ctx.reason_code = "token_active"

        return IntrospectResponse(
            active=True,
            sub=claims.get("sub"),
            client_id=claims.get("client_id"),
            aud=claims.get("aud"),
            task_id=claims.get("task_id"),
            scope=claims.get("scope"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            jti=claims.get("jti"),
            act=claims.get("act"),
        )
    except Exception as exc:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = f"token_inactive_{type(exc).__name__}"
        return IntrospectResponse(active=False)
