"""Client Initiated Backchannel Authentication (CIBA) approval manager and out-of-band push."""

from datetime import datetime, timezone
import json
import time
from typing import Any, Dict, Optional, Tuple
import uuid

from pydantic import BaseModel, Field

from mcp_shield.ciba.totp import DEFAULT_DEV_TOTP_SECRET, verify_totp_code
from mcp_shield.logging import get_access_logger


class CIBAApprovalRequest(BaseModel):
    """Out-of-band approval request schema."""
    auth_req_id: str
    user_id: str
    client_id: str
    session_id: Optional[str] = None
    tool_name: str
    arguments: Dict[str, Any]
    task_description: str
    explanation: str
    is_sensitive: bool = False
    requires_step_up: bool = False
    status: str = Field(default="pending", description="pending, approved, denied, expired")
    created_at: str
    expires_at: float
    slack_payload: Dict[str, Any] = Field(default_factory=dict)
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None


class CIBAManager:
    """Manages out-of-band approvals (CIBA), mobile web interface, and step-up authentication."""

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        self._requests: Dict[str, CIBAApprovalRequest] = {}

    def create_request(
        self,
        user_id: str,
        client_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        task_description: str,
        explanation: str,
        is_sensitive: bool = False,
        session_id: Optional[str] = None,
    ) -> CIBAApprovalRequest:
        """Creates a pending approval request with Slack Block Kit push payload."""
        auth_req_id = f"ciba_{uuid.uuid4().hex[:16]}"
        now = time.time()
        now_utc = datetime.now(timezone.utc).isoformat()
        expires_at = now + self.default_ttl

        # Slack Block Kit notification format
        slack_blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ MCP Shield: Action Approval Required", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Task:*\n{task_description}"},
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Gateway Assessment:*\n{explanation}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Arguments:*\n```{json.dumps(arguments, indent=2)}```",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve ✅"},
                        "style": "primary",
                        "value": f"approve:{auth_req_id}",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny ❌"},
                        "style": "danger",
                        "value": f"deny:{auth_req_id}",
                    },
                ],
            },
        ]

        if is_sensitive:
            slack_blocks.insert(3, {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "⚠️ *Sensitive Operation*: Step-up TOTP verification required to approve."}
                ],
            })

        req = CIBAApprovalRequest(
            auth_req_id=auth_req_id,
            user_id=user_id,
            client_id=client_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            task_description=task_description,
            explanation=explanation,
            is_sensitive=is_sensitive,
            requires_step_up=is_sensitive,
            status="pending",
            created_at=now_utc,
            expires_at=expires_at,
            slack_payload={"blocks": slack_blocks},
        )
        self._requests[auth_req_id] = req

        # Log approval_requested event to access.log
        self._log_event(
            event="approval_requested",
            auth_req_id=auth_req_id,
            user_id=user_id,
            tool=tool_name,
            is_sensitive=is_sensitive,
            requires_step_up=is_sensitive,
        )

        return req

    def get_request(self, auth_req_id: str) -> Optional[CIBAApprovalRequest]:
        req = self._requests.get(auth_req_id)
        if not req:
            return None
        if time.time() > req.expires_at and req.status == "pending":
            req.status = "expired"
        return req

    def resolve_request(
        self,
        auth_req_id: str,
        action: str,  # "approve" or "deny"
        totp_code: Optional[str] = None,
        resolved_by: str = "human_operator",
    ) -> Tuple[bool, str]:
        """Resolves an out-of-band approval request."""
        req = self.get_request(auth_req_id)
        if not req:
            return False, "request_not_found"

        if req.status != "pending":
            return False, f"request_already_{req.status}"

        # If sensitive action is being approved, require valid TOTP step-up
        if action == "approve" and req.requires_step_up:
            if not totp_code or not verify_totp_code(totp_code):
                return False, "invalid_or_missing_totp_code"

        now_utc = datetime.now(timezone.utc).isoformat()
        req.resolved_by = resolved_by
        req.resolved_at = now_utc

        if action == "approve":
            req.status = "approved"
            self._log_event(
                event="approval_approved",
                auth_req_id=auth_req_id,
                user_id=req.user_id,
                tool=req.tool_name,
                resolved_by=resolved_by,
                step_up_verified=req.requires_step_up,
            )
            return True, "approved"
        else:
            req.status = "denied"
            self._log_event(
                event="approval_denied",
                auth_req_id=auth_req_id,
                user_id=req.user_id,
                tool=req.tool_name,
                resolved_by=resolved_by,
            )
            return True, "denied"

    def _log_event(self, event: str, **kwargs) -> None:
        logger = get_access_logger()
        now_utc = datetime.now(timezone.utc).isoformat()
        entry = {
            "ts": now_utc,
            "event": event,
            **kwargs,
        }
        logger.info(json.dumps(entry, separators=(",", ":")))


ciba_manager = CIBAManager()
