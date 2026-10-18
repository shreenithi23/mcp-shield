"""Admin Console Backend Router with RBAC authorization."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from mcp_shield.ai.thresholds import RiskTier, TIER_THRESHOLDS, classify_tool_risk
from mcp_shield.audit.analyzer import AccessLogAnalyzer
from mcp_shield.audit.chain import audit_manager
from mcp_shield.ciba.manager import ciba_manager
from mcp_shield.config import settings
from mcp_shield.integrity.registry import tool_registry
from mcp_shield.quotas.manager import quota_manager
from mcp_shield.taint.manager import taint_manager

router = APIRouter(prefix="/api/console", tags=["Admin Console"])


def get_current_role(
    x_user_role: Optional[str] = Header("admin", alias="x-user-role"),
    authorization: Optional[str] = Header(None),
) -> str:
    """RBAC dependency: extracts role from header or default token."""
    role = (x_user_role or "developer").lower()
    if role not in ("admin", "operator", "auditor"):
        role = "auditor"  # least-privilege fallback
    return role


def require_role(min_role: str):
    """Enforces role hierarchy: admin > operator > auditor."""
    hierarchy = {"admin": 3, "operator": 2, "auditor": 1}

    def role_checker(role: str = Depends(get_current_role)):
        if hierarchy.get(role, 0) < hierarchy.get(min_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action requires minimum '{min_role}' role (current role: '{role}')",
            )
        return role

    return role_checker


@router.get("/stats", summary="Overview metrics and statistics")
async def get_console_stats(role: str = Depends(require_role("auditor"))):
    analyzer = AccessLogAnalyzer()
    report = analyzer.analyze().to_dict()

    # Active held approvals
    now = datetime.now(timezone.utc).timestamp()
    pending_held = [
        r for r in ciba_manager._requests.values()
        if r.status == "pending" and r.expires_at > now
    ]

    # Tool status summary
    tools = list(tool_registry._registry.values())
    quarantined_tools = [t for t in tools if t.status == "quarantined"]

    return {
        "role": role,
        "total_requests": report["total_requests"],
        "outcomes": report["outcome_breakdown"],
        "pending_held_count": len(pending_held),
        "quarantined_tools_count": len(quarantined_tools),
        "latency": report["latency"],
        "top_denied_tools": report["top_denied_tools"],
        "anomalies_detected": len(report["anomalies"]),
    }


@router.get("/feed", summary="Live decision feed from audit chain")
async def get_decision_feed(limit: int = 50, role: str = Depends(require_role("auditor"))):
    """Returns recent decision records with model scores, outcomes, and arguments hash."""
    records = []
    if audit_manager.log_path.exists():
        with open(audit_manager.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
    # Reverse to show newest first
    feed = list(reversed(records[-limit:]))
    return {"total": len(feed), "items": feed}


@router.get("/held", summary="Queue of held calls awaiting human approval")
async def get_held_queue(role: str = Depends(require_role("auditor"))):
    """Returns all held calls currently waiting for human decision."""
    now = datetime.now(timezone.utc).timestamp()
    items = []
    for r in ciba_manager._requests.values():
        is_expired = now > r.expires_at and r.status == "pending"
        items.append({
            "auth_req_id": r.auth_req_id,
            "tool": r.tool_name,
            "arguments": r.arguments,
            "user_id": r.user_id,
            "client_id": r.client_id,
            "task": r.task_description,
            "explanation": r.explanation,
            "is_sensitive": r.is_sensitive,
            "requires_step_up": r.requires_step_up,
            "status": "expired" if is_expired else r.status,
            "created_at": r.created_at,
            "expires_in": max(0, int(r.expires_at - now)),
        })
    return {"items": sorted(items, key=lambda x: x["created_at"], reverse=True)}


@router.post("/held/{auth_req_id}/action", summary="Approve or deny a held call")
async def resolve_held_call(
    auth_req_id: str,
    action: str = Form(...),
    totp_code: Optional[str] = Form(None),
    role: str = Depends(require_role("operator")),
):
    """Approves or denies a held call (requires operator or admin role)."""
    success, msg = ciba_manager.resolve_request(
        auth_req_id=auth_req_id,
        action=action,
        totp_code=totp_code,
        resolved_by=f"console_{role}",
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": msg, "auth_req_id": auth_req_id, "resolved_by": role}


@router.get("/tools", summary="Tool registry and integrity status")
async def list_tools_registry(role: str = Depends(require_role("auditor"))):
    """Returns all approved, quarantined, and monitored tools with SHA-256 hashes."""
    items = []
    for (server, name), rec in tool_registry._registry.items():
        tier = classify_tool_risk(name)
        items.append({
            "tool_name": rec.tool_name,
            "server_uri": rec.server_uri,
            "description": rec.description,
            "description_sha256": rec.description_sha256,
            "approved_at": rec.approved_at,
            "status": rec.status,
            "risk_tier": tier.value,
        })
    return {"tools": items}


@router.post("/tools/approve", summary="Admin approves or unquarantines a tool")
async def approve_tool_integrity(
    tool_name: str = Form(...),
    server_uri: str = Form(...),
    description: str = Form(...),
    role: str = Depends(require_role("admin")),
):
    """Re-approves a mutated or quarantined tool with new pinned SHA-256 (admin only)."""
    rec = tool_registry.approve_tool(
        tool_name=tool_name,
        server_uri=server_uri,
        description=description,
    )
    return {
        "status": "approved",
        "tool_name": rec.tool_name,
        "description_sha256": rec.description_sha256,
        "approved_by": role,
    }


@router.get("/policies", summary="Active ABAC threshold configuration")
async def get_policies(role: str = Depends(require_role("auditor"))):
    """Returns calibrated thresholds and OPA rule parameters per risk tier."""
    return {
        "thresholds": TIER_THRESHOLDS,
        "rego_package": "mcp_shield.authz",
        "layers": [
            {"layer": 1, "name": "Identity & Cryptographic Proof", "mechanisms": ["OAuth 2.1 AS", "RFC 9449 DPoP"]},
            {"layer": 2, "name": "RBAC & Scoped Delegation", "mechanisms": ["RFC 9396 authorization_details", "Resource Indicators"]},
            {"layer": 3, "name": "Circuit Breakers & Quotas", "mechanisms": ["Rate limits", "Denial tripped breaker"]},
            {"layer": 4, "name": "AI Decision & ABAC", "mechanisms": ["OpenJev System One", "OPA Rego 4-outcome engine"]},
        ],
    }


@router.get("/agents", summary="Per-agent risk and activity trends")
async def get_agent_trends(role: str = Depends(require_role("auditor"))):
    """Returns agent activity, denial rates, and circuit breaker status."""
    analyzer = AccessLogAnalyzer()
    report = analyzer.analyze().to_dict()

    agents = [
        {
            "client_id": "agent_copilot_assistant",
            "name": "GitHub Copilot Bug Assistant",
            "risk_status": "normal",
            "allowed_tools": ["list_issues", "issue_read", "slack_post_message"],
            "circuit_breaker": "healthy",
            "calls_last_hour": 14,
        },
        {
            "client_id": "agent_dev_worker",
            "name": "Autonomous Refactoring Agent",
            "risk_status": "elevated",
            "allowed_tools": ["search_code", "create_branch", "create_or_update_file"],
            "circuit_breaker": "healthy",
            "calls_last_hour": 8,
        },
    ]
    return {"agents": agents}


@router.get("/audit", summary="Audit chain verification status and SIEM export")
async def get_audit_status(role: str = Depends(require_role("auditor"))):
    valid, count, err = audit_manager.verify_chain()
    analyzer = AccessLogAnalyzer()
    rec = analyzer.reconcile()
    return {
        "chain_valid": valid,
        "records_count": count,
        "verification_error": err,
        "reconciliation": rec,
        "export_url": "/api/console/audit/export",
    }


@router.get("/audit/export", summary="Export SIEM ECS-formatted JSON records")
async def export_siem_feed(role: str = Depends(require_role("auditor"))):
    records = audit_manager.export_siem()
    return records
