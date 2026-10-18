"""RFC 7009 Token Revocation Endpoint."""

from datetime import datetime, timezone
from typing import Optional
from authlib.jose import jwt
from fastapi import APIRouter, Depends, Form, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_shield.crypto import crypto_manager
from mcp_shield.database import ephemeral_cache, get_db
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.models import IssuedToken

router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])


@router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    summary="RFC 7009 Token Revocation Endpoint",
)
async def revoke_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Revokes an issued token. Per RFC 7009, returns 200 even if token was already revoked or invalid."""
    ctx = current_log_context.get()
    if ctx:
        ctx.args_sha256 = hash_arguments({"token_sha256": hash_arguments(token)})

    jti: Optional[str] = None
    try:
        # Attempt to decode token to retrieve jti
        claims = jwt.decode(token, crypto_manager.get_jwks()["keys"][0])
        jti = claims.get("jti")
    except Exception:
        # If standard verification fails (e.g. expired), attempt unverified extraction
        try:
            unverified = jwt.decode(token, None, options={"verify_signature": False})
            jti = unverified.get("jti")
        except Exception:
            jti = None

    if jti:
        if ctx:
            ctx.token_jti = jti
        
        # Add to fast ephemeral revocation set
        await ephemeral_cache.revoke_jti(jti)

        # Update persistent database record
        stmt = select(IssuedToken).where(IssuedToken.jti == jti)
        res = await db.execute(stmt)
        issued = res.scalar_one_or_none()
        if issued:
            issued.revoked = True
            issued.revoked_at = datetime.now(timezone.utc)
            await db.commit()

    if ctx:
        ctx.outcome = "allow"
        ctx.reason_code = "token_revoked" if jti else "invalid_token_revoke_ignored"

    return {}
