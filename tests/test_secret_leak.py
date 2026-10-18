"""Tests ensuring zero secrets (tokens, PATs, verifiers, client secrets) leak into access.log."""

from pathlib import Path
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import generate_pkce_pair


@pytest.mark.asyncio
async def test_no_secret_values_appear_in_access_log(client: AsyncClient, setup_temp_log_file: str):
    """Fails if any secret token, client_secret, PKCE verifier, or sensitive value leaks to access.log."""
    log_path = Path(setup_temp_log_file)

    # 1. Canary secrets
    canary_client_name = "Canary Secret Agent"
    canary_verifier, canary_challenge = generate_pkce_pair()
    canary_pat = "ghp_canary_secret_pat_99887766554433221100"
    canary_resource = "https://api.githubcopilot.com/mcp/"
    canary_task = "Audit repositories without leaking PAT credentials"

    # 2. Register confidential client to obtain client_secret
    reg_resp = await client.post(
        "/oauth/register",
        json={
            "client_name": canary_client_name,
            "redirect_uris": ["http://localhost:9999/callback"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert reg_resp.status_code == 201
    client_data = reg_resp.json()
    canary_client_id = client_data["client_id"]
    canary_client_secret = client_data["client_secret"]
    assert canary_client_secret is not None

    # 3. Request authorization code
    auth_resp = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": canary_client_id,
            "redirect_uri": "http://localhost:9999/callback",
            "code_challenge": canary_challenge,
            "code_challenge_method": "S256",
            "resource": canary_resource,
            "task_id": canary_task,
            "state": "random_canary_state_123",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    redirect_location = auth_resp.headers["location"]
    # Extract code from redirect URL
    import urllib.parse
    parsed = urllib.parse.urlparse(redirect_location)
    query_params = urllib.parse.parse_qs(parsed.query)
    canary_code = query_params["code"][0]

    # 4. Exchange code for access token
    token_resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": canary_code,
            "redirect_uri": "http://localhost:9999/callback",
            "client_id": canary_client_id,
            "code_verifier": canary_verifier,
            "resource": canary_resource,
        },
    )
    assert token_resp.status_code == 200
    token_data = token_resp.json()
    canary_access_token = token_data["access_token"]

    # 5. Revoke token
    revoke_resp = await client.post(
        "/oauth/revoke",
        data={"token": canary_access_token},
    )
    assert revoke_resp.status_code == 200

    # 6. Introspect token
    intro_resp = await client.post(
        "/oauth/introspect",
        data={"token": canary_access_token},
    )
    assert intro_resp.status_code == 200

    # 7. Check entire access.log content for leak of any sensitive string
    log_content = log_path.read_text(encoding="utf-8")
    lines = [l for l in log_content.splitlines() if l.strip()]
    assert len(lines) >= 5, f"Expected at least 5 logged requests, found {len(lines)}"

    # Assert secrets do NOT appear in log
    assert canary_access_token not in log_content, "Access token leaked into access.log!"
    assert canary_client_secret not in log_content, "Client secret leaked into access.log!"
    assert canary_verifier not in log_content, "PKCE code_verifier leaked into access.log!"
    assert canary_code not in log_content, "Authorization code leaked into access.log!"
    assert canary_pat not in log_content, "Personal access token leaked into access.log!"
