"""Full end-to-end integration test: discovery -> registration -> PKCE -> authorize -> token -> protected call -> revoke."""

import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import generate_pkce_pair


@pytest.mark.asyncio
async def test_full_oauth_lifecycle_flow(client: AsyncClient):
    """Executes the full zero-trust OAuth 2.1 lifecycle flow."""
    target_server = "https://api.githubcopilot.com/mcp/"
    user_task = "Analyze open security vulnerabilities in repo"

    # Step 1: Agent discovers Protected Resource Metadata (RFC 9728) via 401
    unauth_resp = await client.get("/mcp/resource-test", params={"resource_id": target_server})
    assert unauth_resp.status_code == 401
    assert "resource_metadata=" in unauth_resp.headers["www-authenticate"]

    # Step 2: Fetch metadata
    meta_resp = await client.get("/.well-known/oauth-protected-resource")
    assert meta_resp.status_code == 200
    auth_server_url = meta_resp.json()["authorization_servers"][0]
    assert auth_server_url is not None

    # Step 3: Dynamic Client Registration (RFC 7591)
    reg_resp = await client.post(
        "/oauth/register",
        json={
            "client_name": "Autonomous GitHub Agent",
            "redirect_uris": ["http://localhost:8080/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "scope": "mcp",
        },
    )
    assert reg_resp.status_code == 201
    client_id = reg_resp.json()["client_id"]

    # Step 4: PKCE preparation
    verifier, challenge = generate_pkce_pair()

    # Step 5: Authorization Code Request with RFC 8707 Resource & task_id
    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/oauth/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": target_server,
            "task_id": user_task,
            "state": "agent_session_state_xyz",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    redirect_loc = auth_resp.headers["location"]
    parsed = urllib.parse.urlparse(redirect_loc)
    qs = urllib.parse.parse_qs(parsed.query)
    code = qs["code"][0]
    state = qs["state"][0]
    assert state == "agent_session_state_xyz"

    # Step 6: Token Exchange
    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/oauth/callback",
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": target_server,
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()
    access_token = token_data["access_token"]
    assert token_data["resource"] == target_server
    assert token_data["expires_in"] == 300

    # Step 7: Use Token against Protected Resource
    res_resp = await client.get(
        "/mcp/resource-test",
        params={"resource_id": target_server},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert res_resp.status_code == 200
    assert res_resp.json()["status"] == "authorized"
    assert res_resp.json()["task_id"] == user_task

    # Step 8: Introspect Token
    intro_resp = await client.post("/oauth/introspect", data={"token": access_token})
    assert intro_resp.status_code == 200
    assert intro_resp.json()["active"] is True
    assert intro_resp.json()["aud"] == target_server

    # Step 9: Revoke Token
    rev_resp = await client.post("/oauth/revoke", data={"token": access_token})
    assert rev_resp.status_code == 200

    # Step 10: Verify Token is now Inactive
    intro_after = await client.post("/oauth/introspect", data={"token": access_token})
    assert intro_after.status_code == 200
    assert intro_after.json()["active"] is False
