"""Tests for the /demo API router."""

import pytest
from httpx import ASGITransport, AsyncClient
from mcp_shield.main import app


@pytest.mark.asyncio
async def test_demo_scenarios_listing():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/demo/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) == 4
        ids = [s["id"] for s in scenarios]
        assert "benign" in ids
        assert "injection" in ids
        assert "overreach" in ids
        assert "quota" in ids


@pytest.mark.asyncio
async def test_demo_run_benign_scenario():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/demo/scenarios/run/benign",
            json={"instruction": "Summarize issues and post to Slack"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "benign"
        assert len(data["steps"]) == 2
        assert data["steps"][0]["outcome"] == "allow"
        assert data["steps"][1]["outcome"] == "allow"
        assert data["is_tainted"] is False


@pytest.mark.asyncio
async def test_demo_run_injection_scenario():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/demo/scenarios/run/injection",
            json={"instruction": "Analyze issues"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "injection"
        assert len(data["steps"]) == 3
        assert data["steps"][0]["outcome"] == "allow"
        assert data["steps"][1]["outcome"] == "hold"  # Tainted write held
        assert data["steps"][2]["outcome"] == "deny"  # Privilege escalation denied
        assert data["is_tainted"] is True

        # Clear taint
        clear_resp = await client.post(f"/demo/session/{data['session_id']}/clear-taint")
        assert clear_resp.status_code == 200
        assert clear_resp.json()["tainted"] is False


@pytest.mark.asyncio
async def test_demo_malicious_rug_pull_and_reset():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Trigger rug pull
        rp_resp = await client.post("/demo/malicious/rug-pull")
        assert rp_resp.status_code == 200
        rp_data = rp_resp.json()
        assert rp_data["tool_status"] == "quarantined"
        assert rp_data["blocked"] is True

        # Reset clean
        reset_resp = await client.post("/demo/malicious/reset")
        assert reset_resp.status_code == 200
        assert reset_resp.json()["status_code"] == "approved"


@pytest.mark.asyncio
async def test_demo_eval_results_and_quotas():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Eval results
        eval_resp = await client.get("/demo/eval-results")
        assert eval_resp.status_code == 200
        eval_data = eval_resp.json()
        assert "chart_data" in eval_data
        assert "metrics_table" in eval_data
        assert len(eval_data["metrics_table"]) > 5

        # Quotas
        quota_resp = await client.get("/demo/quotas")
        assert quota_resp.status_code == 200
        assert "usage" in quota_resp.json()


@pytest.mark.asyncio
async def test_demo_audit_tamper_and_restore():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Tamper
        t_resp = await client.post("/demo/audit/tamper")
        assert t_resp.status_code == 200
        assert t_resp.json()["status"] == "tampered"

        # Verify chain fails
        audit_resp = await client.get("/api/console/audit")
        assert audit_resp.status_code == 200
        assert audit_resp.json()["chain_valid"] is False

        # 2. Restore
        r_resp = await client.post("/demo/audit/restore")
        assert r_resp.status_code == 200

        # Verify chain valid again
        audit_resp2 = await client.get("/api/console/audit")
        assert audit_resp2.status_code == 200
        assert audit_resp2.json()["chain_valid"] is True
