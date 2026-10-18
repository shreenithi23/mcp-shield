#!/usr/bin/env python3
"""MCP Shield - Standalone Phase 1 Demo & Test Script.

Executes the full zero-trust discovery -> registration -> PKCE -> consent -> token -> verify -> revoke flow.
Works against a running server (e.g. http://localhost:8000) or runs in-process.
"""

import sys
from pathlib import Path

# Add src to python path for standalone execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import urllib.parse
import httpx

from mcp_shield.crypto import generate_pkce_pair


def run_demo(base_url: str = "http://localhost:8000"):
    print("=" * 70)
    print("  MCP SHIELD — PHASE 1 END-TO-END OAUTH 2.1 DEMONSTRATION")
    print("=" * 70)

    target_mcp_server = "https://api.githubcopilot.com/mcp/"
    client_name = "CLI-Autonomous-Agent-01"
    redirect_uri = "http://localhost:8080/callback"
    task_id = "Find and summarize open issues in throwaway-test-repo"

    # Test connectivity; fallback to in-process ASGITransport if server not running
    is_live = False
    try:
        with httpx.Client(base_url=base_url, timeout=1.0) as probe:
            resp = probe.get("/health")
            if resp.status_code == 200:
                is_live = True
    except Exception:
        is_live = False

    if is_live:
        print(f"[*] Connecting to live MCP Shield gateway at {base_url}...")
        client_cm = httpx.Client(base_url=base_url, timeout=10.0)
    else:
        print(f"[*] Live server not detected at {base_url}. Running in-process with TestClient...")
        import asyncio
        from starlette.testclient import TestClient
        from mcp_shield.database import init_db
        from mcp_shield.main import app
        asyncio.run(init_db())
        client_cm = TestClient(app, base_url="http://localhost:8000")

    with client_cm as client:
        # Step 1: Protected Resource Discovery (RFC 9728)
        print("\n[Step 1] Triggering Protected Resource Discovery via 401...")
        unauth_resp = client.get("/mcp/resource-test", params={"resource_id": target_mcp_server})
        print(f"  -> HTTP Status: {unauth_resp.status_code}")
        www_auth = unauth_resp.headers.get("www-authenticate", "")
        print(f"  -> WWW-Authenticate Header: {www_auth}")
        assert unauth_resp.status_code == 401
        assert "resource_metadata=" in www_auth

        # Step 2: Fetch Protected Resource Metadata
        print("\n[Step 2] Fetching Protected Resource Metadata (RFC 9728)...")
        meta_resp = client.get("/.well-known/oauth-protected-resource")
        print(f"  -> Metadata Response: {meta_resp.json()}")
        assert meta_resp.status_code == 200

        # Step 3: Fetch Server JWKS (RFC 7517)
        print("\n[Step 3] Fetching Authorization Server JWKS (RFC 7517)...")
        jwks_resp = client.get("/.well-known/jwks.json")
        print(f"  -> JWKS Public Keys count: {len(jwks_resp.json().get('keys', []))}")
        assert jwks_resp.status_code == 200

        # Step 4: Dynamic Client Registration (RFC 7591)
        print(f"\n[Step 4] Dynamically Registering Client '{client_name}' (RFC 7591)...")
        reg_resp = client.post(
            "/oauth/register",
            json={
                "client_name": client_name,
                "redirect_uris": [redirect_uri],
                "token_endpoint_auth_method": "none",
                "scope": "mcp",
            },
        )
        assert reg_resp.status_code == 201
        reg_data = reg_resp.json()
        client_id = reg_data["client_id"]
        print(f"  -> Registered client_id: {client_id}")

        # Step 5: Generate PKCE Pair (RFC 7636)
        verifier, challenge = generate_pkce_pair()
        print(f"\n[Step 5] Generated PKCE Code Challenge (S256): {challenge[:20]}...")

        # Step 6: Authorization Code Request (RFC 8707 & PKCE)
        print("\n[Step 6] Requesting Authorization Code (Resource-bound to GitHub MCP)...")
        auth_resp = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": target_mcp_server,
                "task_id": task_id,
                "state": "demo_state_999",
            },
            follow_redirects=False,
        )
        assert auth_resp.status_code == 302
        location = auth_resp.headers["location"]
        print(f"  -> Redirect Location: {location}")
        parsed = urllib.parse.urlparse(location)
        code = urllib.parse.parse_qs(parsed.query)["code"][0]
        print(f"  -> Received Auth Code: {code[:16]}... (Redacted)")

        # Step 7: Exchange Code for RS256 JWT Access Token
        print("\n[Step 7] Exchanging Code + PKCE Verifier for Access Token at /oauth/token...")
        token_resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": target_mcp_server,
            },
        )
        assert token_resp.status_code == 200
        token_data = token_resp.json()
        access_token = token_data["access_token"]
        expires_in = token_data["expires_in"]
        print(f"  -> Issued Token Type: {token_data['token_type']}")
        print(f"  -> Expires In: {expires_in} seconds (5 minutes)")
        print(f"  -> Bound Audience: {token_data['resource']}")
        print(f"  -> Token (preview): {access_token[:25]}...{access_token[-10:]}")

        # Step 8: Call Protected Resource with Token
        print("\n[Step 8] Calling Protected Resource for authorized audience (GitHub MCP)...")
        res_resp = client.get(
            "/mcp/resource-test",
            params={"resource_id": target_mcp_server},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        print(f"  -> Status: {res_resp.status_code}")
        print(f"  -> Response: {res_resp.json()}")
        assert res_resp.status_code == 200

        # Step 9: Lateral Movement Test (Resource A vs Resource B)
        print("\n[Step 9] Lateral Movement Test: Using GitHub MCP token against Slack MCP...")
        lateral_resp = client.get(
            "/mcp/resource-test",
            params={"resource_id": "http://localhost:8001/slack-mcp"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        print(f"  -> Status: {lateral_resp.status_code} (Expected 403 Forbidden)")
        print(f"  -> Message: {lateral_resp.json()}")
        assert lateral_resp.status_code == 403

        # Step 10: Introspect Token (RFC 7662)
        print("\n[Step 10] Introspecting Token (RFC 7662)...")
        intro_resp = client.post("/oauth/introspect", data={"token": access_token})
        print(f"  -> Introspection Status: {intro_resp.json()}")
        assert intro_resp.json()["active"] is True

        # Step 11: Revoke Token (RFC 7009)
        print("\n[Step 11] Revoking Token (RFC 7009)...")
        rev_resp = client.post("/oauth/revoke", data={"token": access_token})
        print(f"  -> Revocation Status: {rev_resp.status_code}")
        assert rev_resp.status_code == 200

        # Step 12: Verify Token is now Inactive
        print("\n[Step 12] Verifying Revoked Token fails Introspection...")
        intro_revoked = client.post("/oauth/introspect", data={"token": access_token})
        print(f"  -> Revoked Token Active: {intro_revoked.json()['active']}")
        assert intro_revoked.json()["active"] is False

    print("\n" + "=" * 70)
    print("  ALL DEMO CHECKS PASSED SUCCESSFULLY! ZERO-TRUST FOUNDATION ACTIVE.")
    print("=" * 70)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    run_demo(url)
