"""Tests for RFC 9449 DPoP verification and replay protection."""

import pytest
from mcp_shield.dpop.verifier import DPoPClientKey, dpop_verifier


@pytest.mark.asyncio
async def test_dpop_valid_proof_succeeds():
    """Legitimate DPoP proof with matching method and URL is verified."""
    key = DPoPClientKey()
    url = "http://localhost:8000/mcp/proxy"
    method = "POST"

    proof = key.generate_proof(http_method=method, http_url=url)
    is_valid, jkt, err = await dpop_verifier.verify(
        dpop_header=proof,
        http_method=method,
        http_url=url,
    )

    assert is_valid is True
    assert jkt == key.jkt
    assert err is None


@pytest.mark.asyncio
async def test_dpop_stolen_token_jkt_mismatch_rejected():
    """A token bound to Key A MUST be rejected if presented with DPoP proof signed by Key B."""
    key_alice = DPoPClientKey()
    key_attacker = DPoPClientKey()
    url = "http://localhost:8000/mcp/proxy"

    # Token was issued and bound to Alice's key thumbprint
    alice_token_claims = {
        "sub": "user_alice",
        "cnf": {"jkt": key_alice.jkt},
    }

    # Attacker attempts to present Alice's token using Attacker's DPoP key
    attacker_proof = key_attacker.generate_proof(http_method="POST", http_url=url)

    is_valid, jkt, err = await dpop_verifier.verify(
        dpop_header=attacker_proof,
        http_method="POST",
        http_url=url,
        token_claims=alice_token_claims,
    )

    assert is_valid is False
    assert "dpop_jkt_mismatch" in str(err)


@pytest.mark.asyncio
async def test_dpop_replay_attack_rejected():
    """The same DPoP proof JWT cannot be reused (replay defense)."""
    key = DPoPClientKey()
    url = "http://localhost:8000/mcp/proxy"
    method = "POST"

    proof = key.generate_proof(http_method=method, http_url=url)

    # First presentation succeeds
    valid1, _, _ = await dpop_verifier.verify(dpop_header=proof, http_method=method, http_url=url)
    assert valid1 is True

    # Replayed presentation fails
    valid2, _, err = await dpop_verifier.verify(dpop_header=proof, http_method=method, http_url=url)
    assert valid2 is False
    assert err == "dpop_proof_replayed"


@pytest.mark.asyncio
async def test_dpop_htm_mismatch_rejected():
    """Proof generated for GET must fail when presented on POST."""
    key = DPoPClientKey()
    url = "http://localhost:8000/mcp/proxy"

    proof = key.generate_proof(http_method="GET", http_url=url)
    is_valid, _, err = await dpop_verifier.verify(dpop_header=proof, http_method="POST", http_url=url)

    assert is_valid is False
    assert "htm_mismatch" in str(err)
