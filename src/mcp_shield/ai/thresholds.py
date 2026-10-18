"""Tool Risk Tier classification and ABAC threshold configuration."""

from enum import Enum
from typing import Dict, Set


class RiskTier(str, Enum):
    TIER_1_READ = "read"
    TIER_2_REVERSIBLE_WRITE = "reversible_write"
    TIER_3_IRREVERSIBLE = "irreversible_or_privilege"


# Approved classification of the 46 GitHub MCP tools
TIER_1_TOOLS: Set[str] = {
    "get_commit",
    "get_file_contents",
    "get_label",
    "get_latest_release",
    "get_me",
    "get_release_by_tag",
    "get_tag",
    "get_team_members",
    "get_teams",
    "issue_read",
    "list_branches",
    "list_commits",
    "list_issue_fields",
    "list_issue_types",
    "list_issues",
    "list_pull_requests",
    "list_releases",
    "list_repository_collaborators",
    "list_tags",
    "pull_request_read",
    "search_code",
    "search_commits",
    "search_issues",
    "search_pull_requests",
    "search_repositories",
    "search_users",
    "ui_get",
    "tools/list",
    "initialize",
}

TIER_2_TOOLS: Set[str] = {
    "add_comment_to_pending_review",
    "add_issue_comment",
    "add_reply_to_pull_request_comment",
    "create_branch",
    "create_or_update_file",
    "create_pull_request",
    "issue_write",
    "pull_request_review_write",
    "request_copilot_review",
    "sub_issue_write",
    "update_issue_comment",
    "update_pull_request",
    "update_pull_request_branch",
}

TIER_3_TOOLS: Set[str] = {
    "delete_file",
    "merge_pull_request",
    "push_files",
    "create_repository",
    "fork_repository",
    "run_secret_scanning",
}


def classify_tool_risk(tool_name: str) -> RiskTier:
    """Classifies tool into its corresponding risk tier."""
    clean_name = tool_name.strip()
    if clean_name in TIER_3_TOOLS:
        return RiskTier.TIER_3_IRREVERSIBLE
    if clean_name in TIER_2_TOOLS:
        return RiskTier.TIER_2_REVERSIBLE_WRITE
    if clean_name in TIER_1_TOOLS:
        return RiskTier.TIER_1_READ

    # Heuristic for unknown tools
    lower = clean_name.lower()
    if any(k in lower for k in ["delete", "drop", "destroy", "merge", "admin", "privilege", "secret"]):
        return RiskTier.TIER_3_IRREVERSIBLE
    if any(k in lower for k in ["write", "create", "update", "post", "put", "send", "add"]):
        return RiskTier.TIER_2_REVERSIBLE_WRITE
    return RiskTier.TIER_1_READ


# Calibrated Thresholds per Tier
TIER_THRESHOLDS = {
    RiskTier.TIER_1_READ: {
        "intent_match_min": 0.70,
        "sensitivity_max": 0.80,
        "fallback_on_timeout": "static_allow",
    },
    RiskTier.TIER_2_REVERSIBLE_WRITE: {
        "intent_match_min": 0.90,
        "overreach_max": 0.20,
        "injection_risk_max": 0.10,
        "fallback_on_timeout": "hold",
    },
    RiskTier.TIER_3_IRREVERSIBLE: {
        "always_hold": True,
        "fallback_on_timeout": "hold",
    },
}
