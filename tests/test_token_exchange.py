"""Tests for RFC 8693 Token Exchange and RFC 9396 downscoped authorization_details."""

import json
import urllib.parse
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import crypto_manager, generate_pkce_pair


@pytest.mark.asyncio
async def test_rfc8693_token_exchange_downscoping(client: AsyncClient):
    """Exchanges broad parent token for task-specific downscoped token with RFC 9396 details."""
    verifier, challenge = generate_pkce_pair()
    server_uri = "https://api.githubcopilot.com/mcp/"

    reg = await client.post(
        "/oauth/register",
        json={"client_name": "Exchange Parent Agent", "redirect_uris": ["http://localhost:8080/callback"]},
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
            "resource": server_uri,
            "task_id": "Top level mission: Audit repository",
        },
        follow_redirects=False,
    )
    code = urllib.parse.parse_qs(urllib.parse.urlparse(auth_resp.headers["location"]).query)["code"][0]

    parent_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    parent_token = parent_resp.json()["access_token"]

    # Perform RFC 8693 Token Exchange for a subtask
    subtask_authz = [
        {
            "type": "mcp_tool",
            "server": server_uri,
            "tools": ["list_issues"],
            "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        }
    ]

    exchange_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "task_id": "Subtask: list issues only",
            "authorization_details": json.dumps(subtask_authz),
        },
    )
    assert exchange_resp.status_code == 200
    downscoped_data = exchange_resp.json()
    downscoped_token = downscoped_data["access_token"]

    claims = crypto_manager.verify_access_token(downscoped_token)
    assert claims["task_id"] == "Subtask: list issues only"
    assert claims["authorization_details"] == subtask_authz
    assert claims["act"]["client_id"] == client_id
