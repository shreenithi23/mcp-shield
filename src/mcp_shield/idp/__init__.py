"""IdP Factory for MCP Shield."""

from mcp_shield.config import settings
from mcp_shield.idp.base import BaseIdPProvider
from mcp_shield.idp.mock import MockIdPProvider
from mcp_shield.idp.oidc import StandardOIDCProvider


def get_idp_provider() -> BaseIdPProvider:
    if settings.IDP_PROVIDER == "google":
        return StandardOIDCProvider(
            client_id=settings.IDP_CLIENT_ID or "",
            client_secret=settings.IDP_CLIENT_SECRET or "",
            authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
            provider_name="google",
        )
    elif settings.IDP_PROVIDER == "entra":
        tenant = settings.ENTRA_TENANT_ID or "common"
        return StandardOIDCProvider(
            client_id=settings.IDP_CLIENT_ID or "",
            client_secret=settings.IDP_CLIENT_SECRET or "",
            authorization_endpoint=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            token_endpoint=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            userinfo_endpoint="https://graph.microsoft.com/oidc/userinfo",
            provider_name="entra",
        )
    # Default to mock
    return MockIdPProvider()
