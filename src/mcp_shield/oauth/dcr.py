"""RFC 7591 Dynamic Client Registration endpoint."""

import secrets
import time
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_shield.database import get_db
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.models import Client
from mcp_shield.schemas import (
    ClientRegistrationRequest,
    ClientRegistrationResponse,
)

router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])


@router.post(
    "/register",
    response_model=ClientRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="RFC 7591 Dynamic Client Registration",
)
async def register_client(
    req: ClientRegistrationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Allows AI agents and tools to dynamically register with the authorization server."""
    ctx = current_log_context.get()
    if ctx:
        ctx.args_sha256 = hash_arguments(req.model_dump())

    if not req.redirect_uris:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_redirect_uris"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uris must not be empty",
        )

    client_id = f"client_{uuid.uuid4().hex[:16]}"
    client_secret = None
    if req.token_endpoint_auth_method != "none":
        client_secret = f"sec_{secrets.token_urlsafe(32)}"

    client = Client(
        client_id=client_id,
        client_secret=client_secret,
        client_name=req.client_name,
        redirect_uris=req.redirect_uris,
        grant_types=req.grant_types or ["authorization_code"],
        response_types=req.response_types or ["code"],
        token_endpoint_auth_method=req.token_endpoint_auth_method or "none",
        scope=req.scope or "mcp",
    )

    db.add(client)
    await db.commit()

    if ctx:
        ctx.client_id = client_id
        ctx.outcome = "allow"
        ctx.reason_code = "client_registered"

    return ClientRegistrationResponse(
        client_id=client_id,
        client_secret=client_secret,
        client_name=client.client_name,
        redirect_uris=client.redirect_uris,
        grant_types=client.grant_types,
        response_types=client.response_types,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        scope=client.scope,
        client_id_issued_at=int(time.time()),
    )
