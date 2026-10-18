"""Test suite for Phase 5: Audit Log, Chain Verification, Console API & Evaluation."""

import json
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from mcp_shield.audit.analyzer import AccessLogAnalyzer
from mcp_shield.audit.chain import AuditRecord, AuditTrailManager, GENESIS_HASH
from mcp_shield.eval.dataset import generate_benchmark_dataset
from mcp_shield.eval.harness import eval_runner
from mcp_shield.main import app


@pytest.fixture
def temp_audit_trail(tmp_path: Path):
    """Provides an isolated audit trail file for cryptographic testing."""
    test_log = tmp_path / "test_audit_chain.jsonl"
    manager = AuditTrailManager(log_path=test_log)
    return manager, test_log


def test_audit_chain_append_and_verification(temp_audit_trail):
    """Verifies that appending records creates a cryptographically valid hash chain."""
    manager, log_path = temp_audit_trail

    # 1. Initially empty chain is valid with 0 records
    valid, count, err = manager.verify_chain()
    assert valid is True
    assert count == 0

    # 2. Append first record
    rec0 = manager.append(
        request_id="req-001",
        user_id="usr_alice",
        client_id="agent_01",
        task_id="Audit bugs",
        server="https://api.githubcopilot.com/mcp/",
        tool="list_issues",
        args_sha256="abc123hash",
        model_name="openjev-v1",
        model_version="0.1.0",
        scores={"intent_match": 0.95},
        outcome="allow",
        latency_ms=12.5,
    )
    assert rec0.index == 0
    assert rec0.prev_hash == GENESIS_HASH
    assert len(rec0.record_hash) == 64

    # 3. Append second record
    rec1 = manager.append(
        request_id="req-002",
        user_id="usr_alice",
        client_id="agent_01",
        task_id="Post slack alert",
        server="http://slack-mcp/mcp",
        tool="slack_post_message",
        args_sha256="def456hash",
        model_name="openjev-v1",
        model_version="0.1.0",
        scores={"intent_match": 0.85},
        outcome="hold",
        reason_code="borderline_intent",
        latency_ms=8.2,
    )
    assert rec1.index == 1
    assert rec1.prev_hash == rec0.record_hash

    # 4. Verify chain integrity
    valid, count, err = manager.verify_chain()
    assert valid is True
    assert count == 2
    assert err is None


def test_audit_chain_tamper_detection(temp_audit_trail):
    """Core Acceptance Test: Tampering with any record in the chain is immediately detected."""
    manager, log_path = temp_audit_trail

    # Append 3 valid records
    for i in range(3):
        manager.append(
            request_id=f"req-00{i}",
            user_id="usr_alice",
            client_id="agent_01",
            task_id="Task",
            server="https://api.githubcopilot.com/mcp/",
            tool="list_issues",
            args_sha256="hash",
            model_name="openjev-v1",
            model_version="0.1.0",
            scores={"intent_match": 0.95},
            outcome="allow",
            latency_ms=10.0,
        )

    assert manager.verify_chain()[0] is True

    # Tamper with record #1 by altering outcome from 'allow' to 'deny'
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    tampered_rec = json.loads(lines[1])
    tampered_rec["outcome"] = "deny"  # Tampering with outcome without updating hash
    lines[1] = json.dumps(tampered_rec)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verification must detect tampering
    valid, count, err = manager.verify_chain()
    assert valid is False
    assert "Tampering detected" in err
    assert count == 1  # Record 0 was valid, record 1 was tampered!


def test_siem_export(temp_audit_trail, tmp_path: Path):
    """Verifies that audit records export properly formatted for SIEM (ECS-compliant)."""
    manager, log_path = temp_audit_trail
    manager.append(
        request_id="req-siem-01",
        user_id="usr_dev",
        client_id="agent_01",
        task_id="Task",
        server="https://api.githubcopilot.com/mcp/",
        tool="create_or_update_file",
        args_sha256="hash",
        model_name="openjev-v1",
        model_version="0.1.0",
        scores={"intent_match": 0.9},
        outcome="deny",
        latency_ms=15.0,
        reason_code="policy_denied",
    )

    export_file = tmp_path / "siem_export.json"
    records = manager.export_siem(output_path=export_file)
    assert len(records) == 1
    assert export_file.exists()

    rec = records[0]
    assert "@timestamp" in rec
    assert rec["event"]["id"] == "req-siem-01"
    assert rec["event"]["outcome"] == "failure"
    assert rec["mcp"]["tool"] == "create_or_update_file"
    assert rec["chain"]["record_hash"] is not None


@pytest.mark.asyncio
async def test_console_api_rbac_gating():
    """Verifies that console endpoints strictly enforce RBAC (admin vs operator vs auditor)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Auditor can view stats, feed, tools, policies
        auditor_stats = await client.get("/api/console/stats", headers={"x-user-role": "auditor"})
        assert auditor_stats.status_code == 200

        auditor_feed = await client.get("/api/console/feed", headers={"x-user-role": "auditor"})
        assert auditor_feed.status_code == 200

        # 2. Auditor CANNOT approve tools or resolve held calls
        audit_tool_approve = await client.post(
            "/api/console/tools/approve",
            headers={"x-user-role": "auditor"},
            data={"tool_name": "list_issues", "server_uri": "http://mcp", "description": "desc"},
        )
        assert audit_tool_approve.status_code == 403  # Requires admin

        audit_held_resolve = await client.post(
            "/api/console/held/fake_id/action",
            headers={"x-user-role": "auditor"},
            data={"action": "approve"},
        )
        assert audit_held_resolve.status_code == 403  # Requires operator

        # 3. Admin can approve tools
        admin_tool_approve = await client.post(
            "/api/console/tools/approve",
            headers={"x-user-role": "admin"},
            data={"tool_name": "new_tool", "server_uri": "http://mcp", "description": "approved desc"},
        )
        assert admin_tool_approve.status_code == 200
        assert admin_tool_approve.json()["status"] == "approved"


def test_benchmark_dataset_generation():
    """Verifies that the benchmark dataset contains exactly 300 labeled samples."""
    samples = generate_benchmark_dataset()
    assert len(samples) == 300

    categories = {s["category"] for s in samples}
    assert categories == {"benign_read", "benign_write", "prompt_injection", "poisoned_tools", "overreach_actions"}

    benign_count = sum(1 for s in samples if s["ground_truth"] == "benign")
    attack_count = sum(1 for s in samples if s["ground_truth"] == "attack")

    assert benign_count == 120  # 75 read + 45 write
    assert attack_count == 180  # 80 injection + 50 poisoned + 50 overreach


@pytest.mark.asyncio
async def test_evaluation_runner_generates_chart():
    """Verifies that running the evaluation produces comparative metrics and ROC SVG chart."""
    res = await eval_runner.run_all()
    assert "models" in res
    assert "jev" in res["models"]
    assert "decision_1" in res["models"]
    assert "general_llm" in res["models"]

    # Verify ROC chart was generated
    chart_path = Path(res["chart_path"])
    assert chart_path.exists()
    assert "<svg" in chart_path.read_text(encoding="utf-8")
