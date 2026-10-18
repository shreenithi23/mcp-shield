"""Tests for OAuth 2.1 PKCE enforcement (RFC 7636)."""

import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import generate_pkce_pair


@pytest.mark.asyncio
async def test_pkce_plain_method_rejected(client: AsyncClient):
    """OAuth 2.1 strictly rejects 'plain' code_challenge_method."""
    reg = await client.post(
        "/oauth/register",
        json={"client_name": "PKCE Agent", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]

    resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": "plain_challenge_string",
            "code_challenge_method": "plain",  # Plain method forbidden
            "resource": "https://api.githubcopilot.com/mcp/",
            "task_id": "pkce test",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "code_challenge_method must be 'S256'" in resp.text


@pytest.mark.asyncio
async def test_pkce_missing_challenge_rejected(client: AsyncClient):
    """Missing code_challenge is rejected."""
    reg = await client.post(
        "/oauth/register",
        json={"client_name": "PKCE Agent 2", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]

    resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": "",
            "code_challenge_method": "S256",
            "resource": "https://api.githubcopilot.com/mcp/",
            "task_id": "pkce test",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_pkce_invalid_verifier_rejected_at_token_endpoint(client: AsyncClient):
    """Token exchange fails when code_verifier does not match code_challenge."""
    verifier, challenge = generate_pkce_pair()
    wrong_verifier, _ = generate_pkce_pair()

    reg = await client.post(
        "/oauth/register",
        json={"client_name": "PKCE Agent 3", "redirect_uris": ["http://localhost:8080/callback"]},
    )
    client_id = reg.json()["client_id"]

    # Authorize with legitimate challenge
    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://api.githubcopilot.com/mcp/",
            "task_id": "pkce test",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    parsed = urllib.parse.urlparse(auth_resp.headers["location"])
    code = urllib.parse.parse_qs(parsed.query)["code"][0]

    # Attempt token exchange with wrong verifier
    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": client_id,
            "code_verifier": wrong_verifier,  # Incorrect verifier
        },
    )
    assert token_resp.status_code == 400
    assert "PKCE code_verifier verification failed" in token_resp.text


@pytest.mark.asyncio
async def test_pkce_valid_verifier_succeeds(client: AsyncClient):
    """Token exchange succeeds with correct S256 code_verifier."""
    verifier, challenge = generate_pkce_pair()

    reg = await client.post(
        "/oauth/register",
        json={"client_name": "PKCE Success Agent", "redirect_uris": ["http://localhost:8080/callback"]},
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
            "task_id": "pkce test success",
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
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
