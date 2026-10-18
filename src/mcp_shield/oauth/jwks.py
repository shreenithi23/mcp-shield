"""JWKS Endpoint exposing RS256 public key (RFC 7517)."""

from fastapi import APIRouter
from mcp_shield.crypto import crypto_manager
from mcp_shield.logging import current_log_context

router = APIRouter(tags=["Cryptographic Keys"])


@router.get("/.well-known/jwks.json", summary="JSON Web Key Set (RFC 7517)")
async def get_jwks():
    """Returns the gateway's public RSA signing keys for token verification."""
    ctx = current_log_context.get()
    if ctx:
        ctx.outcome = "allow"
        ctx.reason_code = "jwks_fetched"
    return crypto_manager.get_jwks()
