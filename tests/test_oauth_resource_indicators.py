"""Tests for RFC 8707 Resource Indicators and strict audience binding."""

import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import generate_pkce_pair


@pytest.mark.asyncio
async def test_token_for_resource_a_is_rejected_for_resource_b(client: AsyncClient):
    """Core Acceptance Test: A token bound to Resource A MUST fail when used for Resource B."""
    resource_a = "https://api.githubcopilot.com/mcp/"
    resource_b = "http://localhost:8001/slack-mcp"
    task_id = "Analyze GitHub repositories"

    # 1. Register Client
    reg = await client.post(
        "/oauth/register",
        json={"client_name": "Resource Tester", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]
    verifier, challenge = generate_pkce_pair()

    # 2. Authorize specifically for Resource A
    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource_a,  # Resource A
            "task_id": task_id,
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # 3. Exchange code for access token
    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource_a,
        },
    )
    assert token_resp.status_code == 200
    token_a = token_resp.json()["access_token"]

    # 4. Access Resource A -> MUST SUCCEED (200)
    res_a_call = await client.get(
        "/mcp/resource-test",
        params={"resource_id": resource_a},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_a_call.status_code == 200
    data_a = res_a_call.json()
    assert data_a["status"] == "authorized"
    assert data_a["resource"] == resource_a
    assert data_a["task_id"] == task_id

    # 5. Access Resource B with Token A -> MUST BE REJECTED (403 Forbidden with audience mismatch)
    res_b_call = await client.get(
        "/mcp/resource-test",
        params={"resource_id": resource_b},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_b_call.status_code == 403
    assert "Audience mismatch" in res_b_call.text


@pytest.mark.asyncio
async def test_token_request_with_wrong_resource_mismatch_fails(client: AsyncClient):
    """If client requests code for Resource A but tries to claim Resource B at /oauth/token, it fails."""
    resource_a = "https://api.githubcopilot.com/mcp/"
    resource_b = "http://localhost:8001/slack-mcp"

    reg = await client.post(
        "/oauth/register",
        json={"client_name": "Mismatch Tester", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]
    verifier, challenge = generate_pkce_pair()

    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource_a,
            "task_id": "mismatch check",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # Attempt to swap resource at token exchange
    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource_b,  # Swapped resource
        },
    )
    assert token_resp.status_code == 400
    assert "invalid_target" in token_resp.text
