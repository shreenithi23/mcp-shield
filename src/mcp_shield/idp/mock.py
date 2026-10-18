"""Mock Identity Provider for local development and offline automated testing."""

from urllib.parse import urlencode
from typing import Any, Dict
from mcp_shield.config import settings
from mcp_shield.idp.base import BaseIdPProvider


class MockIdPProvider(BaseIdPProvider):
    """Simulates upstream IdP (Google / Entra) without external network dependencies."""

    def __init__(self):
        self.default_user = {
            "email": "agent.operator@example.com",
            "name": "Operator Alice",
            "provider_sub": "mock-sub-12345",
            "provider": "mock",
        }

    def get_login_url(self, state: str, redirect_uri: str) -> str:
        # Directs to mock callback endpoint on the gateway itself
        params = {
            "state": state,
            "redirect_uri": redirect_uri,
            "code": "mock_upstream_auth_code_xyz",
        }
        return f"{settings.BASE_URL}/mock-idp/login?{urlencode(params)}"

    async def exchange_code_for_user(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        # Accepts any valid mock code
        return {
            "email": self.default_user["email"],
            "name": self.default_user["name"],
            "provider_sub": self.default_user["provider_sub"],
            "provider": "mock",
        }
