"""Standard OIDC Identity Provider integration (Google / Microsoft Entra)."""

from urllib.parse import urlencode
from typing import Any, Dict
import httpx

from mcp_shield.config import settings
from mcp_shield.idp.base import BaseIdPProvider


class StandardOIDCProvider(BaseIdPProvider):
    """Integrates with standard OIDC identity providers (Google / Microsoft Entra)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        provider_name: str = "oidc",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.provider_name = provider_name

    def get_login_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    async def exchange_code_for_user(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(
                self.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()
            access_token = tokens["access_token"]

            user_resp = await client.get(
                self.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_resp.raise_for_status()
            info = user_resp.json()

            return {
                "email": info.get("email"),
                "name": info.get("name"),
                "provider_sub": info.get("sub"),
                "provider": self.provider_name,
            }
