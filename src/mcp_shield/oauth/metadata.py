"""Protected Resource Metadata (RFC 9728) and OAuth Server Metadata (RFC 8414)."""

from fastapi import APIRouter
from mcp_shield.config import settings
from mcp_shield.schemas import ProtectedResourceMetadata

router = APIRouter(tags=["Metadata"])


@router.get(
    "/.well-known/oauth-protected-resource",
    response_model=ProtectedResourceMetadata,
    summary="RFC 9728 Protected Resource Metadata",
)
async def get_protected_resource_metadata():
    """Returns protected resource metadata including authorization server location."""
    return ProtectedResourceMetadata(
        resource=f"{settings.BASE_URL}/mcp",
        authorization_servers=[settings.BASE_URL],
        scopes_supported=["mcp", "tools:read", "tools:call"],
        bearer_methods_supported=["header"],
        resource_documentation=f"{settings.BASE_URL}/docs",
    )


@router.get(
    "/.well-known/oauth-authorization-server",
    summary="RFC 8414 OAuth 2.0 Authorization Server Metadata",
)
@router.get(
    "/.well-known/openid-configuration",
    summary="OpenID Connect Discovery Document",
)
async def get_oauth_server_metadata():
    """Returns RFC 8414 OAuth 2.0 Authorization Server Metadata."""
    return {
        "issuer": settings.BASE_URL,
        "authorization_endpoint": f"{settings.BASE_URL}/oauth/authorize",
        "token_endpoint": f"{settings.BASE_URL}/oauth/token",
        "registration_endpoint": f"{settings.BASE_URL}/oauth/register",
        "revocation_endpoint": f"{settings.BASE_URL}/oauth/revoke",
        "introspection_endpoint": f"{settings.BASE_URL}/oauth/introspect",
        "jwks_uri": f"{settings.BASE_URL}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp", "openid", "profile", "email"],
    }
