"""Taint tracking state machine and automated token downscoping (RFC 8693)."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple
import uuid

from mcp_shield.ai.thresholds import TIER_1_TOOLS
from mcp_shield.config import settings
from mcp_shield.crypto import crypto_manager
from mcp_shield.database import ephemeral_cache
from mcp_shield.logging import get_access_logger


class TaintRecord:
    def __init__(
        self,
        session_id: str,
        reason: str,
        source_tool: str,
        tainted_at: str,
        downscoped_token: Optional[str] = None,
    ):
        self.session_id = session_id
        self.reason = reason
        self.source_tool = source_tool
        self.tainted_at = tainted_at
        self.downscoped_token = downscoped_token

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "reason": self.reason,
            "source_tool": self.source_tool,
            "tainted_at": self.tainted_at,
            "downscoped_token": self.downscoped_token,
        }


class TaintManager:
    """Manages session taint state, automated RFC 8693 read-only token exchange, and audit logging."""

    async def is_session_tainted(self, session_id: Optional[str]) -> bool:
        """Returns True if the session is tainted."""
        if not session_id:
            return False
        val = await ephemeral_cache.get(f"session_tainted:{session_id}")
        return val is not None

    async def get_taint_info(self, session_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Returns taint metadata for a session if tainted."""
        if not session_id:
            return None
        val = await ephemeral_cache.get(f"session_tainted:{session_id}")
        if not val:
            return None
        try:
            return json.loads(val)
        except Exception:
            return {"tainted": True, "reason": val}

    async def set_session_tainted(
        self,
        session_id: str,
        reason: str,
        source_tool: str,
        current_token: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Marks session tainted, downscopes token to read-only via RFC 8693, and logs event.
        
        Returns:
            (taint_data: Dict[str, Any], downscoped_token: Optional[str])
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        downscoped_token = None

        # Automated RFC 8693 Token Exchange downscoping to read-only tools
        if current_token:
            try:
                parent_claims = crypto_manager.verify_access_token(current_token)
                authz_details = parent_claims.get("authorization_details", [])
                readonly_authz: List[Dict[str, Any]] = []

                for detail in authz_details:
                    tools = detail.get("tools", [])
                    # Filter tools to only Tier 1 read-only tools
                    ro_tools = [t for t in tools if t in TIER_1_TOOLS or "read" in t.lower() or "list" in t.lower()]
                    if ro_tools:
                        new_detail = dict(detail)
                        new_detail["tools"] = ro_tools
                        readonly_authz.append(new_detail)

                user_id = parent_claims.get("sub", "user")
                client_id = parent_claims.get("client_id", "agent")
                target_resource = parent_claims.get("aud")
                task_id = f"DOWN-SCOPED READ-ONLY: {parent_claims.get('task_id', '')} (Tainted session {session_id})"
                jti = str(uuid.uuid4())

                downscoped_token = crypto_manager.sign_access_token(
                    sub=user_id,
                    client_id=client_id,
                    aud=target_resource,
                    task_id=task_id,
                    expires_in=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                    jti=jti,
                    dpop_jkt=parent_claims.get("cnf", {}).get("jkt"),
                    authorization_details=readonly_authz,
                )
            except Exception:
                downscoped_token = None

        record_data = {
            "session_id": session_id,
            "tainted": True,
            "reason": reason,
            "source_tool": source_tool,
            "tainted_at": now_utc,
            "has_downscoped_token": downscoped_token is not None,
        }

        # Store in cache with 1-hour expiration
        await ephemeral_cache.set(
            f"session_tainted:{session_id}",
            json.dumps(record_data),
            ex=3600,
        )

        # Log taint_set event to access.log
        self._log_taint_event(
            event="taint_set",
            session_id=session_id,
            reason=reason,
            source_tool=source_tool,
        )

        return record_data, downscoped_token

    async def clear_session_taint(
        self,
        session_id: str,
        cleared_by: str,
        reason: str = "Administrator cleared taint after manual security verification",
    ) -> bool:
        """Clears session taint and records audit event."""
        exists = await self.is_session_tainted(session_id)
        if not exists:
            return False

        await ephemeral_cache.delete(f"session_tainted:{session_id}")

        self._log_taint_event(
            event="taint_cleared",
            session_id=session_id,
            cleared_by=cleared_by,
            reason=reason,
        )
        return True

    def _log_taint_event(self, event: str, session_id: str, **kwargs) -> None:
        """Emits structured taint lifecycle event to access.log."""
        logger = get_access_logger()
        now_utc = datetime.now(timezone.utc).isoformat()
        entry = {
            "ts": now_utc,
            "event": event,
            "session_id": session_id,
            **kwargs,
        }
        logger.info(json.dumps(entry, separators=(",", ":")))


taint_manager = TaintManager()
