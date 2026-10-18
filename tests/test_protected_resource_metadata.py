"""Tests for RFC 9728 Protected Resource Metadata and Discovery Flow."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_protected_resource_metadata_endpoint(client: AsyncClient):
    """GET /.well-known/oauth-protected-resource returns valid RFC 9728 schema."""
    resp = await client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert "resource" in data
    assert "authorization_servers" in data
    assert isinstance(data["authorization_servers"], list)
    assert len(data["authorization_servers"]) > 0
    assert "scopes_supported" in data
    assert "bearer_methods_supported" in data


@pytest.mark.asyncio
async def test_rfc9728_discovery_flow_401_header(client: AsyncClient):
    """Unauthenticated access returns 401 with WWW-Authenticate header containing resource_metadata."""
    resp = await client.get("/mcp/resource-test", params={"resource_id": "https://api.githubcopilot.com/mcp/"})
    assert resp.status_code == 401
    www_auth = resp.headers.get("www-authenticate")
    assert www_auth is not None
    assert "Bearer" in www_auth
    assert 'resource_metadata="' in www_auth
    assert "/.well-known/oauth-protected-resource" in www_auth
