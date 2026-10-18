"""Reverse Proxy Policy Enforcement Point (PEP) for Streamable HTTP MCP servers."""

import json
from typing import Any, Dict, Optional
import httpx
from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse

from mcp_shield.ai.checkpoints import checkpoint_evaluator
from mcp_shield.ai.thresholds import RiskTier, classify_tool_risk
from mcp_shield.ciba.manager import ciba_manager
from mcp_shield.config import settings
from mcp_shield.crypto import crypto_manager
from mcp_shield.database import ephemeral_cache
from mcp_shield.demo_servers.malicious_server import malicious_mcp_app
from mcp_shield.demo_servers.postgres_server import postgres_mcp_app
from mcp_shield.demo_servers.slack_server import slack_mcp_app
from mcp_shield.dpop.verifier import dpop_verifier
from mcp_shield.explanations.generator import explanation_generator
from mcp_shield.integrity.registry import tool_registry
from mcp_shield.logging import current_log_context, hash_arguments
from mcp_shield.policies.evaluator import opa_evaluator
from mcp_shield.quotas.manager import quota_manager
from mcp_shield.taint.manager import taint_manager
from mcp_shield.vault.vault import credential_vault

router = APIRouter(prefix="/mcp", tags=["Policy Enforcement Point"])


@router.post(
    "/proxy",
    summary="Reverse Proxy Policy Enforcement Point for Streamable HTTP MCP",
)
async def mcp_reverse_proxy(
    request: Request,
    authorization: Optional[str] = Header(None),
    dpop: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="mcp-session-id"),
):
    """Enforces zero-trust DPoP, PBAC, quotas, swaps credentials, and proxies to upstream MCP server."""
    ctx = current_log_context.get()
    raw_body = await request.body()

    # 1. Authenticate Agent Bearer Token
    if not authorization or not (authorization.startswith("Bearer ") or authorization.startswith("DPoP ")):
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "missing_authorization_header"
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{settings.BASE_URL}/.well-known/oauth-protected-resource", error="unauthorized"'
            },
            content=json.dumps({"error": "unauthorized", "message": "Bearer or DPoP token required"}),
            media_type="application/json",
        )

    parts = authorization.split(" ", 1)
    auth_scheme = parts[0]
    token = parts[1].strip()

    try:
        token_claims = crypto_manager.verify_access_token(token)
    except Exception as exc:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = f"invalid_token: {str(exc)}"
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json.dumps({"error": "invalid_token", "message": str(exc)}),
            media_type="application/json",
        )

    jti = token_claims.get("jti")
    if jti and await ephemeral_cache.is_jti_revoked(jti):
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = "token_revoked"
        return Response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json.dumps({"error": "invalid_token", "message": "Token has been revoked"}),
            media_type="application/json",
        )

    # 2. DPoP Proof Verification (RFC 9449)
    cnf = token_claims.get("cnf")
    if cnf and cnf.get("jkt"):
        # DPoP proof is strictly mandatory for DPoP-bound tokens
        if not dpop:
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "missing_dpop_proof"
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": 'DPoP error="invalid_dpop_proof", error_description="DPoP proof required"'},
                content=json.dumps({"error": "invalid_dpop_proof", "message": "Missing DPoP proof for bound token"}),
                media_type="application/json",
            )

        valid_dpop, presented_jkt, dpop_err = await dpop_verifier.verify(
            dpop_header=dpop,
            http_method=request.method,
            http_url=str(request.url),
            token_claims=token_claims,
        )
        if not valid_dpop:
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = f"dpop_verification_failed: {dpop_err}"
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": f'DPoP error="invalid_dpop_proof", error_description="{dpop_err}"'},
                content=json.dumps({"error": "invalid_dpop_proof", "message": dpop_err}),
                media_type="application/json",
            )
        if ctx:
            ctx.dpop_ok = True

    # Parse MCP JSON-RPC Payload
    try:
        rpc_payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        rpc_payload = {}

    req_id = rpc_payload.get("id")
    method = rpc_payload.get("method", "unknown")
    params = rpc_payload.get("params", {})
    tool_name = params.get("name") if method == "tools/call" else method
    arguments = params.get("arguments", {}) if method == "tools/call" else {}

    client_id = token_claims.get("client_id", "unknown_agent")
    user_id = token_claims.get("sub", "unknown_user")
    server_uri = token_claims.get("aud")  # e.g. https://api.githubcopilot.com/mcp/

    if ctx:
        ctx.user_id = user_id
        ctx.client_id = client_id
        ctx.task_id = token_claims.get("task_id")
        ctx.mcp_server = server_uri
        ctx.tool = tool_name
        ctx.token_jti = jti
        ctx.args_sha256 = hash_arguments(arguments if method == "tools/call" else rpc_payload)

    # 3. Layer 3: Quota & Circuit Breaker Check
    is_write = any(w in tool_name.lower() for w in ["write", "create", "delete", "push", "update", "merge"])
    quota_ok, quota_reason, retry_after = await quota_manager.check(
        client_id=client_id,
        user_id=user_id,
        tool=tool_name,
        is_write=is_write,
    )
    if not quota_ok:
        if ctx:
            ctx.outcome = "deny"
            ctx.reason_code = quota_reason
        resp_headers = {"Retry-After": str(retry_after or 60)}
        return Response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=resp_headers,
            content=json.dumps({
                "error": "rate_limited",
                "reason": quota_reason,
                "retry_after_seconds": retry_after or 60,
            }),
            media_type="application/json",
        )

    # 4. Layer 2 PBAC & Layer 4 ABAC (Decision Model Checkpoint 1 & OPA) on tools/call
    if method == "tools/call":
        risk_tier = classify_tool_risk(tool_name)

        # Check if current session was tainted by prior tool result injection
        is_session_tainted = False
        if mcp_session_id:
            is_session_tainted = await taint_manager.is_session_tainted(mcp_session_id)

        # Verify tool integrity status (quarantined check)
        record = tool_registry.get_tool(server_uri, tool_name)
        if record and record.status == "quarantined":
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = "tool_integrity_violation_quarantined"
            explanation = await explanation_generator.generate_explanation(
                outcome="deny",
                reason="tool_integrity_violation_quarantined",
                tool_name=tool_name,
                arguments=arguments,
                is_tainted=is_session_tainted,
                risk_tier=risk_tier.value,
            )
            return Response(
                status_code=status.HTTP_403_FORBIDDEN,
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": "Tool quarantined due to unapproved description mutation or hash mismatch",
                        "data": {
                            "tool": tool_name,
                            "explanation": explanation,
                            "outcome": "deny",
                            "reason": "tool_quarantined_due_to_unapproved_mutation",
                        },
                    },
                }),
                media_type="application/json",
            )

        # Checkpoint 1: Evaluate Tool Call via Decision Model within 150ms timeout
        task_desc = token_claims.get("task_id", "") or f"Execute tool {tool_name}"
        scores, cp1_resp = await checkpoint_evaluator.evaluate_tool_call(
            task_id=task_desc,
            tool_name=tool_name,
            arguments=arguments,
            server_uri=server_uri,
            user_id=user_id,
            session_id=mcp_session_id,
        )
        timed_out = cp1_resp.timed_out

        if ctx:
            ctx.scores = {
                "checkpoint": 1,
                "model_name": cp1_resp.model_name,
                "model_version": cp1_resp.model_version,
                "latency_ms": round(cp1_resp.latency_ms, 2),
                "timed_out": timed_out,
                **scores,
            }

        user_roles = ["admin"] if "admin" in user_id or user_id == "usr_operator" else ["developer"]
        developer_allowed_tools = [
            "list_issues", "issue_read", "issue_write", "create_issue", "update_issue",
            "list_branches", "list_commits", "list_tags", "get_file", "search_code",
            "search_repositories", "search_issues", "search_pull_requests", "search_users",
            "tools/list", "initialize", "notifications/initialized", "delete_file",
            "create_branch", "create_or_update_file", "create_pull_request",
            "slack_post_message", "slack_read_channel", "query_readonly", "execute_dml",
            "summarize_text",
        ]

        rego_input = {
            "user": {
                "id": user_id,
                "roles": user_roles,
                "allowed_tools": developer_allowed_tools,
            },
            "agent": {
                "client_id": client_id,
                "task_id": token_claims.get("task_id", ""),
            },
            "token": {
                "authorization_details": token_claims.get("authorization_details", []),
            },
            "action": {
                "server": server_uri,
                "tool": tool_name,
                "permission": f"{'slack' if 'slack' in server_uri else ('postgres' if 'postgres' in server_uri else 'github')}:{tool_name}:{'write' if is_write else 'read'}",
                "risk_tier": risk_tier.value,
            },
            "arguments": arguments,
            "session": {"tainted": is_session_tainted},
            "model": {"timed_out": timed_out},
            "scores": scores,
        }

        outcome, policy_allowed, policy_reason = opa_evaluator.evaluate(rego_input)

        # Outcome 1: DENY (Static denial, severe intent mismatch, or prompt injection)
        if outcome == "deny":
            await quota_manager.record_denial(client_id)
            if ctx:
                ctx.outcome = "deny"
                ctx.reason_code = f"policy_denied_{policy_reason}"
            explanation = await explanation_generator.generate_explanation(
                outcome="deny",
                reason=policy_reason,
                tool_name=tool_name,
                arguments=arguments,
                is_tainted=is_session_tainted,
                risk_tier=risk_tier.value,
            )
            return Response(
                status_code=status.HTTP_403_FORBIDDEN,
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"Zero-trust policy denied tool execution: {policy_reason}",
                        "data": {
                            "tool": tool_name,
                            "reason": policy_reason,
                            "explanation": explanation,
                            "outcome": "deny",
                        },
                    },
                }),
                media_type="application/json",
            )

        # Outcome 2: HOLD (Tier 3 high-risk, write timeout fail-closed, tainted write, borderline score)
        if outcome == "hold":
            if ctx:
                ctx.outcome = "hold"
                ctx.reason_code = policy_reason
            is_sensitive = (risk_tier == RiskTier.TIER_3_IRREVERSIBLE or is_session_tainted)
            explanation = await explanation_generator.generate_explanation(
                outcome="hold",
                reason=policy_reason,
                tool_name=tool_name,
                arguments=arguments,
                is_tainted=is_session_tainted,
                risk_tier=risk_tier.value,
            )
            ciba_req = ciba_manager.create_request(
                user_id=user_id,
                client_id=client_id,
                tool_name=tool_name,
                arguments=arguments,
                task_description=task_desc,
                explanation=explanation,
                is_sensitive=is_sensitive,
                session_id=mcp_session_id,
            )
            return Response(
                status_code=status.HTTP_202_ACCEPTED,
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "status": "hold_for_approval",
                        "auth_req_id": ciba_req.auth_req_id,
                        "tool": tool_name,
                        "risk_tier": risk_tier.value,
                        "reason": policy_reason,
                        "explanation": explanation,
                        "approval_url": f"{settings.BASE_URL}/approval/ui/{ciba_req.auth_req_id}",
                        "requires_step_up": is_sensitive,
                        "slack_notification": ciba_req.slack_payload,
                        "message": "Tool execution is held for human authorization approval before proceeding.",
                    },
                }),
                media_type="application/json",
            )

        # Outcome 3: ALLOW_NARROWER (Paginate / clamp limit to 10 or restrict scope)
        if outcome == "allow_narrower":
            if ctx:
                ctx.outcome = "allow_narrower"
                ctx.reason_code = policy_reason
            if "limit" in arguments and isinstance(arguments["limit"], (int, float)) and arguments["limit"] > 10:
                arguments["limit"] = 10
                if "params" in rpc_payload and "arguments" in rpc_payload["params"]:
                    rpc_payload["params"]["arguments"]["limit"] = 10
                    raw_body = json.dumps(rpc_payload).encode("utf-8")

        # Outcome 4: ALLOW
        if outcome == "allow":
            if ctx:
                ctx.outcome = "allow"
                ctx.reason_code = policy_reason

    # Policy Allowed / Narrowed: Reset circuit breaker denial counter
    await quota_manager.record_success(client_id)

    # 5. Credential Swapping: Retrieve secret from Vault (Never forward agent's token upstream)
    upstream_credential = credential_vault.get_credential(server_uri=server_uri, user_id=user_id)
    if not upstream_credential:
        if ctx:
            ctx.outcome = "error"
            ctx.reason_code = "missing_vault_credential"
        return Response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": "Gateway error: No upstream credential configured in vault for target server",
                },
            }),
            media_type="application/json",
        )

    # 6. Proxy Request Upstream to Remote MCP Server
    upstream_headers = {
        "Authorization": f"Bearer {upstream_credential}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if mcp_session_id:
        upstream_headers["Mcp-Session-Id"] = mcp_session_id

    # Support ASGI transport dispatch for local demo servers
    demo_transports = {
        "http://slack-mcp": httpx.ASGITransport(app=slack_mcp_app),
        "http://postgres-mcp": httpx.ASGITransport(app=postgres_mcp_app),
        "http://malicious-mcp": httpx.ASGITransport(app=malicious_mcp_app),
    }

    transport = None
    for prefix, t in demo_transports.items():
        if server_uri.startswith(prefix):
            transport = t
            break

    client_kwargs = {"timeout": 30.0}
    if transport is not None:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        try:
            upstream_resp = await client.post(
                server_uri,
                headers=upstream_headers,
                content=raw_body,
            )
        except Exception as exc:
            if ctx:
                ctx.outcome = "error"
                ctx.reason_code = f"upstream_connection_failed: {type(exc).__name__}"
            return Response(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": f"Failed to connect to upstream MCP server: {str(exc)}",
                    },
                }),
                media_type="application/json",
            )

    if ctx:
        ctx.upstream_status = upstream_resp.status_code

    # 7. Error Mapping for GitHub Rate Limits & Permission Errors
    if upstream_resp.status_code == 403:
        if ctx:
            ctx.outcome = "error"
            ctx.reason_code = "upstream_403_forbidden"
        return Response(
            status_code=status.HTTP_403_FORBIDDEN,
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32003,
                    "message": "Upstream GitHub MCP rejected request: 403 Forbidden (check fine-grained PAT repository scopes)",
                },
            }),
            media_type="application/json",
        )

    if upstream_resp.status_code == 429:
        if ctx:
            ctx.outcome = "error"
            ctx.reason_code = "upstream_429_rate_limited"
        return Response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": "Upstream GitHub MCP rate limit exceeded (429). Please back off.",
                },
            }),
            media_type="application/json",
        )

    # 8. Checkpoint 2: Tool Result Evaluation (injection_risk, sensitivity)
    downscoped_token = None
    if method == "tools/call" and upstream_resp.status_code == 200:
        try:
            content_str = upstream_resp.content.decode("utf-8", errors="replace")
            task_desc = token_claims.get("task_id", "") or f"Execute tool {tool_name}"
            cp2_scores, cp2_resp = await checkpoint_evaluator.evaluate_tool_result(
                tool_name=tool_name,
                result_content=content_str,
                task_id=task_desc,
                session_id=mcp_session_id,
            )
            if ctx and ctx.scores is not None:
                ctx.scores["checkpoint_2"] = {
                    "model_name": cp2_resp.model_name,
                    "model_version": cp2_resp.model_version,
                    "latency_ms": round(cp2_resp.latency_ms, 2),
                    "timed_out": cp2_resp.timed_out,
                    **cp2_scores,
                }

            inj_risk = cp2_scores.get("injection_risk", 0.0)
            if mcp_session_id and inj_risk >= 0.50:
                taint_rec, downscoped_token = await taint_manager.set_session_tainted(
                    session_id=mcp_session_id,
                    reason=f"High prompt injection risk ({inj_risk:.2f}) detected in output of {tool_name}",
                    source_tool=tool_name,
                    current_token=token,
                )
        except Exception:
            pass

    # 9. Tool Integrity Verification on tools/list discovery
    if method == "tools/list" and upstream_resp.status_code == 200:
        try:
            list_data = json.loads(upstream_resp.content.decode("utf-8"))
            tools_list = list_data.get("result", {}).get("tools", [])
            for t in tools_list:
                t_name = t.get("name")
                t_desc = t.get("description", "")
                if t_name:
                    valid, reason, record = tool_registry.verify_tool_integrity(
                        server_uri=server_uri,
                        tool_name=t_name,
                        current_description=t_desc,
                    )
                    if not valid and reason == "tool_description_hash_mismatch_detected":
                        # Trigger background re-scoring (poisoning_risk, semantic_drift)
                        import asyncio
                        asyncio.create_task(
                            checkpoint_evaluator.evaluate_tool_registration(
                                tool_name=t_name,
                                schema=t.get("inputSchema", {}),
                                description=t_desc,
                                baseline_description=record.description if record else None,
                            )
                        )
        except Exception:
            pass

    # 10. Return Upstream Response (preserving session headers & SSE format)
    response_headers = {}
    new_session_id = upstream_resp.headers.get("mcp-session-id")
    if new_session_id:
        response_headers["Mcp-Session-Id"] = new_session_id

    if downscoped_token:
        response_headers["X-Downscoped-Token"] = downscoped_token

    content_type = upstream_resp.headers.get("content-type", "application/json")

    if ctx:
        if ctx.outcome not in ("allow_narrower", "hold"):
            ctx.outcome = "allow"
        ctx.reason_code = "upstream_success"

    return Response(
        status_code=upstream_resp.status_code,
        headers=response_headers,
        content=upstream_resp.content,
        media_type=content_type,
    )
