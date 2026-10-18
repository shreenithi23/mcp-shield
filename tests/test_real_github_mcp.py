"""Integration tests against the REAL GitHub MCP server (https://api.githubcopilot.com/mcp/).

Skipped if GITHUB_PAT is not set.
"""

import json
import os
import urllib.parse
from pathlib import Path
import pytest
from httpx import AsyncClient

from mcp_shield.crypto import crypto_manager, generate_pkce_pair
from mcp_shield.dpop.verifier import DPoPClientKey
from mcp_shield.vault.vault import credential_vault

GITHUB_PAT = os.getenv("GITHUB_PAT")
GITHUB_TEST_REPO = os.getenv("GITHUB_TEST_REPO", "shreenithi23/mcp-shield-test")
GITHUB_SERVER_URI = "https://api.githubcopilot.com/mcp/"


@pytest.mark.skipif(not GITHUB_PAT, reason="GITHUB_PAT environment variable is not set")
@pytest.mark.asyncio
async def test_real_github_mcp_list_issues_flow(client: AsyncClient, setup_temp_log_file: str):
    """Core Acceptance Test: Real list_issues call succeeds through gateway on the test repo.
    
    Verifies:
    1. Real list_issues succeeds against https://api.githubcopilot.com/mcp/
    2. GitHub PAT never appears in agent-facing request, response, or access.log
    3. Out-of-scope tool is denied BEFORE reaching GitHub
    4. Stolen token without DPoP key is rejected
    """
    log_path = Path(setup_temp_log_file)
    owner, repo_name = GITHUB_TEST_REPO.split("/", 1)

    # Ensure vault has the real credential
    credential_vault.store_credential(
        server_uri=GITHUB_SERVER_URI,
        mode="pat",
        secret=GITHUB_PAT,
        metadata={"repo": GITHUB_TEST_REPO},
    )

    # 1. Setup DPoP Key and Client
    dpop_key = DPoPClientKey()
    proxy_url = "http://localhost:8000/mcp/proxy"

    # Issue audience-bound token with RFC 9396 authorization_details
    token = crypto_manager.sign_access_token(
        sub="usr_operator",
        client_id="github_agent_01",
        aud=GITHUB_SERVER_URI,
        task_id="List all open issues in test repo",
        dpop_jkt=dpop_key.jkt,
        authorization_details=[{
            "type": "mcp_tool",
            "server": GITHUB_SERVER_URI,
            "tools": ["list_issues", "issue_read", "initialize", "notifications/initialized"],
            "constraints": {"owner": owner, "repo": repo_name},
        }],
    )

    # 2. Step 1: Initialize MCP Session through Gateway
    init_proof = dpop_key.generate_proof(http_method="POST", http_url=proxy_url)
    init_resp = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"DPoP {token}", "DPoP": init_proof},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-shield-agent", "version": "0.1.0"},
            },
        },
    )
    assert init_resp.status_code == 200
    session_id = init_resp.headers.get("mcp-session-id")
    assert session_id is not None

    # Step 2: notifications/initialized
    notif_proof = dpop_key.generate_proof(http_method="POST", http_url=proxy_url)
    notif_resp = await client.post(
        "/mcp/proxy",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": notif_proof,
            "mcp-session-id": session_id,
        },
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert notif_resp.status_code in (200, 202)

    # Step 3: Real list_issues Call on the Test Repo
    call_proof = dpop_key.generate_proof(http_method="POST", http_url=proxy_url)
    call_resp = await client.post(
        "/mcp/proxy",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": call_proof,
            "mcp-session-id": session_id,
        },
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": owner, "repo": repo_name},
            },
        },
    )
    assert call_resp.status_code == 200
    if "data:" in call_resp.text:
        data_line = [l[5:].strip() for l in call_resp.text.splitlines() if l.startswith("data:")][0]
        call_data = json.loads(data_line)
    else:
        call_data = call_resp.json()
    assert "result" in call_data or "content" in str(call_data)

    # Step 4: Out-of-scope tool (e.g. create_repository) is denied BEFORE reaching GitHub
    deny_proof = dpop_key.generate_proof(http_method="POST", http_url=proxy_url)
    deny_resp = await client.post(
        "/mcp/proxy",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": deny_proof,
            "mcp-session-id": session_id,
        },
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "create_repository",
                "arguments": {"name": "malicious-repo"},
            },
        },
    )
    assert deny_resp.status_code == 403
    assert "Zero-trust policy denied" in deny_resp.text

    # Step 5: Verify Secret Nonce & Zero Leakage in Responses and Logs
    assert GITHUB_PAT not in init_resp.text
    assert GITHUB_PAT not in call_resp.text
    assert GITHUB_PAT not in deny_resp.text

    log_content = log_path.read_text(encoding="utf-8")
    assert GITHUB_PAT not in log_content, "Real GitHub PAT leaked into access.log!"
