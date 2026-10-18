"""Tests for RFC 7009 Revocation and RFC 7662 Introspection."""

import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import generate_pkce_pair


@pytest.mark.asyncio
async def test_revocation_and_introspection_flow(client: AsyncClient):
    """Token can be introspected, revoked, and once revoked fails resource calls."""
    verifier, challenge = generate_pkce_pair()
    target_resource = "https://api.githubcopilot.com/mcp/"
    task_id = "Inspect PR #42"

    reg = await client.post(
        "/oauth/register",
        json={"client_name": "Revoke Tester", "redirect_uris": ["http://localhost:8080/callback"]},
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
            "resource": target_resource,
            "task_id": task_id,
        },
        follow_redirects=False,
    )
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
    access_token = token_resp.json()["access_token"]

    # 1. Introspect active token
    intro1 = await client.post("/oauth/introspect", data={"token": access_token})
    assert intro1.status_code == 200
    info1 = intro1.json()
    assert info1["active"] is True
    assert info1["aud"] == target_resource
    assert info1["task_id"] == task_id
    assert info1["client_id"] == client_id

    # 2. Revoke token
    rev_resp = await client.post("/oauth/revoke", data={"token": access_token})
    assert rev_resp.status_code == 200

    # 3. Introspect revoked token -> must be inactive
    intro2 = await client.post("/oauth/introspect", data={"token": access_token})
    assert intro2.status_code == 200
    assert intro2.json()["active"] is False

    # 4. Access protected resource with revoked token -> must fail
    res_call = await client.get(
        "/mcp/resource-test",
        params={"resource_id": target_resource},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert res_call.status_code == 401
    assert "revoked" in res_call.text.lower()
