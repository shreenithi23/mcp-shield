"""Tool Integrity Registry with SHA-256 Description Pinning and Drift Detection."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from mcp_shield.logging import get_access_logger


class ToolIntegrityRecord(BaseModel):
    """Integrity record for an approved MCP tool."""
    tool_name: str
    server_uri: str
    description: str
    description_sha256: str
    approved_at: str
    status: str = Field(default="approved", description="approved, unapproved, quarantined")
    last_drift_score: Optional[float] = None
    last_poisoning_score: Optional[float] = None


class ToolIntegrityRegistry:
    """Pins SHA-256 hashes of tool descriptions at approval; flags rug pulls and triggers re-scoring."""

    def __init__(self):
        self._registry: Dict[Tuple[str, str], ToolIntegrityRecord] = {}

    @staticmethod
    def compute_sha256(text: str) -> str:
        """Computes SHA-256 hex digest of string."""
        return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()

    def approve_tool(
        self,
        tool_name: str,
        server_uri: str,
        description: str,
    ) -> ToolIntegrityRecord:
        """Approves a tool and pins its description SHA-256."""
        now_utc = datetime.now(timezone.utc).isoformat()
        digest = self.compute_sha256(description)
        record = ToolIntegrityRecord(
            tool_name=tool_name,
            server_uri=server_uri,
            description=description,
            description_sha256=digest,
            approved_at=now_utc,
            status="approved",
        )
        self._registry[(server_uri, tool_name)] = record
        return record

    def get_tool(self, server_uri: str, tool_name: str) -> Optional[ToolIntegrityRecord]:
        return self._registry.get((server_uri, tool_name))

    def verify_tool_integrity(
        self,
        server_uri: str,
        tool_name: str,
        current_description: str,
    ) -> Tuple[bool, str, Optional[ToolIntegrityRecord]]:
        """Verifies if tool description matches its pinned SHA-256 hash.
        
        Returns:
            (valid: bool, reason: str, record: Optional[ToolIntegrityRecord])
        """
        record = self.get_tool(server_uri, tool_name)
        if not record:
            # Tool has never been approved
            return False, "tool_not_approved_in_registry", None

        if record.status == "quarantined":
            return False, "tool_quarantined_due_to_unapproved_mutation", record

        current_digest = self.compute_sha256(current_description)
        if current_digest != record.description_sha256:
            # Rug pull / poisoned description detected!
            record.status = "quarantined"
            self._log_hash_mismatch(server_uri, tool_name, record.description_sha256, current_digest)
            return False, "tool_description_hash_mismatch_detected", record

        return True, "ok", record

    def _log_hash_mismatch(
        self,
        server_uri: str,
        tool_name: str,
        expected_sha: str,
        actual_sha: str,
    ) -> None:
        """Logs security alert to access.log."""
        logger = get_access_logger()
        now_utc = datetime.now(timezone.utc).isoformat()
        entry = {
            "ts": now_utc,
            "event": "tool_hash_mismatch",
            "server": server_uri,
            "tool": tool_name,
            "expected_sha256": expected_sha,
            "actual_sha256": actual_sha,
            "action": "quarantined_and_blocked",
        }
        logger.warning(json.dumps(entry, separators=(",", ":")))


tool_registry = ToolIntegrityRegistry()


def initialize_catalog_hashes() -> None:
    """Pre-seeds tool registry with discovered GitHub tools and demo server tools."""
    # Seed GitHub tools
    tools_file = Path(__file__).resolve().parents[3] / "discovered_github_tools.json"
    if tools_file.exists():
        try:
            tools = json.loads(tools_file.read_text(encoding="utf-8"))
            for t in tools:
                name = t.get("name")
                desc = t.get("description", "")
                if name:
                    tool_registry.approve_tool(
                        tool_name=name,
                        server_uri="https://api.githubcopilot.com/mcp/",
                        description=desc,
                    )
        except Exception:
            pass

    # Seed Slack demo tools
    tool_registry.approve_tool(
        tool_name="slack_post_message",
        server_uri="http://slack-mcp/mcp",
        description="Post a message to a Slack channel",
    )
    tool_registry.approve_tool(
        tool_name="slack_read_channel",
        server_uri="http://slack-mcp/mcp",
        description="Read messages from a Slack channel",
    )

    # Seed Postgres demo tools
    tool_registry.approve_tool(
        tool_name="query_readonly",
        server_uri="http://postgres-mcp/mcp",
        description="Execute a read-only SQL query against Postgres database",
    )
    tool_registry.approve_tool(
        tool_name="execute_dml",
        server_uri="http://postgres-mcp/mcp",
        description="Execute an INSERT/UPDATE/DELETE query against Postgres database",
    )

    # Seed initial malicious server tool BEFORE it undergoes rug pull
    tool_registry.approve_tool(
        tool_name="summarize_text",
        server_uri="http://malicious-mcp/mcp",
        description="Legitimate text summarization utility for documents",
    )


# Automatically initialize catalog
initialize_catalog_hashes()
