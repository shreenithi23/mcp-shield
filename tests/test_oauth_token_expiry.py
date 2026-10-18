"""Tests for 5-minute token expiration enforcement."""

import time
import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import crypto_manager, generate_pkce_pair


@pytest.mark.asyncio
async def test_tokens_issued_with_5_minute_lifetime(client: AsyncClient):
    """Tokens must have an expires_in of 300 seconds and exp - iat == 300."""
    verifier, challenge = generate_pkce_pair()
    reg = await client.post(
        "/oauth/register",
        json={"client_name": "Expiry Agent", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]

    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://api.githubcopilot.com/mcp/",
            "task_id": "check token lifetime",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    code = urllib.parse.parse_qs(parsed.query)["code"][0]

    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    data = token_resp.json()
    assert data["expires_in"] == 300  # 5 minutes in seconds

    # Decode and check claims
    claims = crypto_manager.verify_access_token(data["access_token"])
    assert claims["exp"] - claims["iat"] == 300


@pytest.mark.asyncio
async def test_expired_token_is_rejected(client: AsyncClient):
    """Expired tokens must fail introspection and resource access."""
    # Create an artificially expired token (-10 seconds)
    expired_token = crypto_manager.sign_access_token(
        sub="usr_expired",
        client_id="client_expired",
        aud="https://api.githubcopilot.com/mcp/",
        task_id="expired task",
        expires_in=-10,
    )

    # Introspection returns active: false
    intro_resp = await client.post(
        "/oauth/introspect",
        data={"token": expired_token},
    )
    assert intro_resp.status_code == 200
    assert intro_resp.json()["active"] is False

    # Resource access returns 401 Unauthorized
    res_resp = await client.get(
        "/mcp/resource-test",
        params={"resource_id": "https://api.githubcopilot.com/mcp/"},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_resp.status_code == 401
    assert "invalid_token" in res_resp.text
