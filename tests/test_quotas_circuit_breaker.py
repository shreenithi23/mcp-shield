"""Tests for Layer 3 Quotas and Circuit Breaker."""

import pytest
from mcp_shield.quotas.manager import QuotaAndCircuitBreakerManager


@pytest.mark.asyncio
async def test_quota_calls_per_min_limit():
    """Exceeding calls per minute threshold triggers quota breach."""
    qm = QuotaAndCircuitBreakerManager(calls_per_min=3)
    client_id = "test_rate_agent"
    tool = "list_issues"

    # Calls 1, 2, 3 succeed
    for _ in range(3):
        ok, reason, _ = await qm.check(client_id, "usr_1", tool)
        assert ok is True

    # 4th call breaches quota
    ok, reason, retry_after = await qm.check(client_id, "usr_1", tool)
    assert ok is False
    assert "quota_exceeded" in str(reason)
    assert retry_after is not None


@pytest.mark.asyncio
async def test_circuit_breaker_trips_after_repeated_denials():
    """Five consecutive policy denials trip circuit breaker to OPEN."""
    qm = QuotaAndCircuitBreakerManager(circuit_breaker_denial_threshold=5, circuit_breaker_cooldown_seconds=30)
    client_id = "denial_prone_agent"

    # Record 4 denials -> not yet tripped
    for _ in range(4):
        tripped = await qm.record_denial(client_id)
        assert tripped is False

    # 5th denial trips circuit breaker
    tripped = await qm.record_denial(client_id)
    assert tripped is True

    # Subsequent check is rejected with circuit_breaker_open
    ok, reason, cooldown = await qm.check(client_id, "usr_1", "list_issues")
    assert ok is False
    assert "circuit_breaker_open" in str(reason)
    assert cooldown is not None
