"""Tests for structured access logging and format verification."""

import json
from pathlib import Path
import pytest
from httpx import AsyncClient

EXPECTED_FIELDS = {
    "ts",
    "request_id",
    "user_id",
    "client_id",
    "task_id",
    "remote_ip",
    "method",
    "path",
    "mcp_server",
    "tool",
    "token_jti",
    "dpop_ok",
    "outcome",
    "reason_code",
    "http_status",
    "upstream_status",
    "args_sha256",
    "scores",
    "latency_ms",
}


@pytest.mark.asyncio
async def test_access_log_generated_for_every_endpoint(client: AsyncClient, setup_temp_log_file: str):
    """Every request hitting the gateway must output a valid JSON line to access.log."""
    log_path = Path(setup_temp_log_file)
    
    # 1. Health check call
    resp1 = await client.get("/health")
    assert resp1.status_code == 200

    # 2. JWKS call
    resp2 = await client.get("/.well-known/jwks.json")
    assert resp2.status_code == 200

    # 3. 404 call
    resp3 = await client.get("/non-existent-endpoint")
    assert resp3.status_code == 404

    # Verify log lines
    assert log_path.exists()
    lines = [l.strip() for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 3

    for line in lines:
        entry = json.loads(line)
        # Check all required fields are present
        assert EXPECTED_FIELDS.issubset(entry.keys())
        assert entry["outcome"] in ("allow", "allow_narrower", "hold", "deny", "error")
        assert isinstance(entry["latency_ms"], (int, float))
        assert entry["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_access_log_argument_hashing(client: AsyncClient, setup_temp_log_file: str):
    """Verifies args_sha256 is a 64-character SHA-256 hex string and never raw data."""
    log_path = Path(setup_temp_log_file)

    payload = {
        "client_name": "Test Logging Agent",
        "redirect_uris": ["http://localhost:8080/callback"],
    }
    resp = await client.post("/oauth/register", json=payload)
    assert resp.status_code == 201

    lines = [l.strip() for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    last_line = json.loads(lines[-1])
    
    assert last_line["path"] == "/oauth/register"
    assert last_line["args_sha256"] is not None
    assert len(last_line["args_sha256"]) == 64  # Valid SHA-256 hex length
    assert "Test Logging Agent" not in lines[-1]  # Raw argument text not in json line
