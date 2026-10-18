"""Tests for Reverse Proxy Policy Enforcement Point (PEP) using Stub MCP server."""

import json
import pytest
from httpx import ASGITransport, AsyncClient

from mcp_shield.crypto import crypto_manager
from mcp_shield.dpop.verifier import DPoPClientKey
from mcp_shield.vault.vault import credential_vault
from tests.stub_mcp_server import stub_mcp_app


@pytest.fixture(autouse=True)
def setup_stub_upstream(monkeypatch):
    """Intercepts upstream calls to http://stub-mcp/mcp and routes them to stub_mcp_app."""
    import httpx
    real_transport = httpx.AsyncHTTPTransport()
    stub_transport = ASGITransport(app=stub_mcp_app)

    class MultiplexTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if "stub-mcp" in str(request.url):
                return await stub_transport.handle_async_request(request)
            return await real_transport.handle_async_request(request)

    real_async_client = AsyncClient

    def custom_client_factory(*args, **kwargs):
        return real_async_client(transport=MultiplexTransport(), *args, **kwargs)

    monkeypatch.setattr("httpx.AsyncClient", custom_client_factory)

    # Store stub credential in vault
    credential_vault.store_credential(
        server_uri="http://stub-mcp/mcp",
        mode="pat",
        secret="stub_upstream_pat_secret_9999",
        metadata={"repo": "shreenithi23/mcp-shield-test"},
    )


@pytest.mark.asyncio
async def test_pep_out_of_scope_tool_denied_before_upstream(client: AsyncClient):
    """An out-of-scope tool (e.g. delete_file) is denied by PBAC before reaching upstream."""
    token = crypto_manager.sign_access_token(
        sub="usr_dev",
        client_id="agent_01",
        aud="http://stub-mcp/mcp",
        task_id="Audit open issues",
        authorization_details=[{
            "type": "mcp_tool",
            "server": "http://stub-mcp/mcp",
            "tools": ["list_issues"],  # Only list_issues permitted
            "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        }],
    )

    # Agent attempts to call delete_file
    resp = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "delete_file",
                "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test", "path": "README.md"},
            },
        },
    )
    assert resp.status_code == 403
    data = resp.json()
    assert "Zero-trust policy denied" in data["error"]["message"]
    assert any(r in data["error"]["message"] for r in ["tool_not_granted_in_token", "user_lacks_delegation_authority"])


@pytest.mark.asyncio
async def test_pep_argument_constraint_repo_mismatch_denied(client: AsyncClient):
    """Attempting to access an unauthorized repository is rejected before reaching upstream."""
    token = crypto_manager.sign_access_token(
        sub="usr_dev",
        client_id="agent_01",
        aud="http://stub-mcp/mcp",
        task_id="Audit open issues",
        authorization_details=[{
            "type": "mcp_tool",
            "server": "http://stub-mcp/mcp",
            "tools": ["list_issues"],
            "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        }],
    )

    resp = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": "unauthorized-org", "repo": "private-vault"},
            },
        },
    )
    assert resp.status_code == 403
    assert "argument_constraint_violated" in resp.text


@pytest.mark.asyncio
async def test_pep_legitimate_tool_call_succeeds_with_credential_swapped(client: AsyncClient):
    """Legitimate call is authorized, credential is swapped, and response returned."""
    token = crypto_manager.sign_access_token(
        sub="usr_dev",
        client_id="agent_01",
        aud="http://stub-mcp/mcp",
        task_id="Audit open issues",
        authorization_details=[{
            "type": "mcp_tool",
            "server": "http://stub-mcp/mcp",
            "tools": ["list_issues"],
            "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        }],
    )

    resp = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "result" in data
    assert "Zero-trust verification issue" in str(data)


@pytest.mark.asyncio
async def test_pep_dpop_enforcement(client: AsyncClient):
    """DPoP bound token requires matching DPoP proof; stolen token without DPoP key fails."""
    key = DPoPClientKey()
    proxy_url = "http://localhost:8000/mcp/proxy"

    # Issue DPoP-bound token
    dpop_token = crypto_manager.sign_access_token(
        sub="usr_dev",
        client_id="agent_01",
        aud="http://stub-mcp/mcp",
        task_id="Audit open issues",
        dpop_jkt=key.jkt,
        authorization_details=[{
            "type": "mcp_tool",
            "server": "http://stub-mcp/mcp",
            "tools": ["list_issues"],
            "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        }],
    )

    # 1. Missing DPoP proof -> 401
    resp_no_dpop = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"DPoP {dpop_token}"},
        json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    )
    assert resp_no_dpop.status_code == 401
    assert "invalid_dpop_proof" in resp_no_dpop.text

    # 2. Presenting valid DPoP proof -> 200
    proof = key.generate_proof(http_method="POST", http_url=proxy_url)
    resp_valid = await client.post(
        "/mcp/proxy",
        headers={
            "Authorization": f"DPoP {dpop_token}",
            "DPoP": proof,
        },
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
            },
        },
    )
    assert resp_valid.status_code == 200


@pytest.mark.asyncio
async def test_pep_upstream_rate_limit_mapped_to_429(client: AsyncClient):
    """Upstream 429 rate limit is mapped to a clear gateway error."""
    token = crypto_manager.sign_access_token(
        sub="usr_dev",
        client_id="agent_01",
        aud="http://stub-mcp/mcp",
        task_id="Audit open issues",
        authorization_details=[{
            "type": "mcp_tool",
            "server": "http://stub-mcp/mcp",
            "tools": ["list_issues"],
            "constraints": {"owner": "shreenithi23", "repo": "simulate-rate-limit"},
        }],
    )

    resp = await client.post(
        "/mcp/proxy",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": "shreenithi23", "repo": "simulate-rate-limit"},
            },
        },
    )
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.text
