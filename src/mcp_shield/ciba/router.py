"""FastAPI routes for CIBA out-of-band approvals and mobile web UI."""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse

from mcp_shield.ciba.manager import ciba_manager
from mcp_shield.taint.manager import taint_manager

router = APIRouter(tags=["CIBA Approvals & Taint"])


@router.post("/ciba/bc-authorize", summary="RFC 8935 CIBA Backchannel Authentication Endpoint")
async def ciba_bc_authorize(
    user_id: str = Form(...),
    client_id: str = Form(...),
    scope: str = Form("mcp"),
    tool: str = Form(...),
    binding_message: Optional[str] = Form(None),
):
    """Initiates an out-of-band approval flow for an agent tool call."""
    req = ciba_manager.create_request(
        user_id=user_id,
        client_id=client_id,
        tool_name=tool,
        arguments={},
        task_description=binding_message or "Execute tool operation",
        explanation="Action held pending backchannel authorization.",
        is_sensitive=False,
    )
    return {
        "auth_req_id": req.auth_req_id,
        "expires_in": ciba_manager.default_ttl,
        "interval": 5,
    }


@router.get("/ciba/request/{auth_req_id}", summary="Check status of an approval request")
async def get_ciba_status(auth_req_id: str):
    req = ciba_manager.get_request(auth_req_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return req


@router.get("/approval/ui/{auth_req_id}", response_class=HTMLResponse, summary="Mobile web approval interface")
async def approval_mobile_ui(auth_req_id: str):
    """Renders a clean, responsive mobile web app for one-tap human authorization."""
    req = ciba_manager.get_request(auth_req_id)
    if not req:
        return HTMLResponse("<h2>Approval request not found or expired.</h2>", status_code=404)

    step_up_html = ""
    if req.requires_step_up and req.status == "pending":
        step_up_html = """
        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px;">
            <p style="margin: 0 0 8px 0; font-weight: 600; color: #856404;">⚠️ Step-up Authentication Required</p>
            <p style="margin: 0 0 8px 0; font-size: 13px; color: #856404;">Enter your 6-digit TOTP code to approve this sensitive action:</p>
            <input type="text" name="totp_code" placeholder="000000" maxlength="6" pattern="[0-9]{6}"
                   style="width: 140px; padding: 8px; font-size: 18px; letter-spacing: 4px; text-align: center; border: 1px solid #ced4da; border-radius: 4px;" />
        </div>
        """

    status_badge = f'<span style="background: #007bff; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px;">{req.status.upper()}</span>'
    if req.status == "approved":
        status_badge = '<span style="background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px;">APPROVED ✅</span>'
    elif req.status == "denied":
        status_badge = '<span style="background: #dc3545; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px;">DENIED ❌</span>'

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />
        <title>MCP Shield Approval</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8f9fa; margin: 0; padding: 16px; color: #212529; }}
            .card {{ background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); padding: 20px; max-width: 480px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e9ecef; padding-bottom: 12px; }}
            .btn {{ flex: 1; padding: 12px; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; }}
            .btn-approve {{ background: #28a745; color: white; margin-right: 8px; }}
            .btn-deny {{ background: #dc3545; color: white; }}
            pre {{ background: #f1f3f5; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="header">
                <h3 style="margin: 0;">🛡️ MCP Shield</h3>
                {status_badge}
            </div>
            <h4>Action Approval Request</h4>
            <p><strong>Task:</strong> {req.task_description}</p>
            <p><strong>Tool:</strong> <code>{req.tool_name}</code></p>
            <div style="background: #e8f4fd; border-left: 4px solid #007bff; padding: 10px; border-radius: 4px; font-size: 13px;">
                <strong>Explanation:</strong> {req.explanation}
            </div>
            <p style="margin-bottom: 4px;"><strong>Arguments:</strong></p>
            <pre>{req.arguments}</pre>

            <form method="POST" action="/approval/action/{auth_req_id}">
                {step_up_html}
                <div style="display: flex; margin-top: 16px;">
                    <button type="submit" name="action" value="approve" class="btn btn-approve">Approve ✅</button>
                    <button type="submit" name="action" value="deny" class="btn btn-deny">Deny ❌</button>
                </div>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@router.post("/approval/action/{auth_req_id}", summary="Process human approval action")
async def process_approval_action(
    auth_req_id: str,
    action: str = Form(...),
    totp_code: Optional[str] = Form(None),
):
    """Processes approve or deny action with step-up verification."""
    success, msg = ciba_manager.resolve_request(
        auth_req_id=auth_req_id,
        action=action,
        totp_code=totp_code,
        resolved_by="human_operator",
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": msg, "auth_req_id": auth_req_id}


@router.post("/mcp/taint/clear", summary="Clear session taint state")
async def clear_session_taint(
    session_id: str = Form(...),
    cleared_by: str = Form("administrator"),
    reason: str = Form("Manual administrator verification completed"),
):
    """Clears taint on a session and restores normal write permissions."""
    cleared = await taint_manager.clear_session_taint(
        session_id=session_id,
        cleared_by=cleared_by,
        reason=reason,
    )
    if not cleared:
        return {"status": "not_tainted", "session_id": session_id}
    return {"status": "cleared", "session_id": session_id}
