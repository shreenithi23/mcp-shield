package mcp_shield.authz_test

import future.keywords.if
import data.mcp_shield.authz

# Test 1: Tier 1 Read is auto-allowed
test_tier1_read_allowed if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["list_issues"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["list_issues"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "list_issues",
            "permission": "github:list_issues:read",
            "risk_tier": "read"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        "session": {"tainted": false},
        "model": {"timed_out": false},
        "scores": {"intent_match": 0.95, "overreach": 0.05, "injection_risk": 0.01, "sensitivity": 0.10}
    }
    authz.outcome == "allow" with input as test_input
}

# Test 2: Tier 2 Write auto-allowed with high intent & low injection risk
test_tier2_write_auto_allowed if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["issue_write"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["issue_write"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "issue_write",
            "permission": "github:issue_write:write",
            "risk_tier": "reversible_write"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test", "title": "Bug"},
        "session": {"tainted": false},
        "model": {"timed_out": false},
        "scores": {"intent_match": 0.95, "overreach": 0.10, "injection_risk": 0.02}
    }
    authz.outcome == "allow" with input as test_input
}

# Test 3: Tier 3 Irreversible tool is ALWAYS HELD regardless of perfect scores
test_tier3_always_held_regardless_of_scores if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["delete_file"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["delete_file"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "delete_file",
            "permission": "github:delete_file:write",
            "risk_tier": "irreversible_or_privilege"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test", "path": "file.txt"},
        "session": {"tainted": false},
        "model": {"timed_out": false},
        "scores": {"intent_match": 1.0, "overreach": 0.0, "injection_risk": 0.0}
    }
    authz.outcome == "hold" with input as test_input
    authz.reason == "high_risk_tier_requires_human_approval" with input as test_input
}

# Test 4: Model timeout holds writes
test_model_timeout_holds_writes if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["issue_write"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["issue_write"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "issue_write",
            "permission": "github:issue_write:write",
            "risk_tier": "reversible_write"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        "session": {"tainted": false},
        "model": {"timed_out": true},
        "scores": {}
    }
    authz.outcome == "hold" with input as test_input
    authz.reason == "model_timeout_write_held" with input as test_input
}

# Test 5: Model timeout allows read-only tools if static policy permits
test_model_timeout_allows_reads if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["list_issues"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["list_issues"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "list_issues",
            "permission": "github:list_issues:read",
            "risk_tier": "read"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        "session": {"tainted": false},
        "model": {"timed_out": true},
        "scores": {}
    }
    authz.outcome == "allow" with input as test_input
    authz.reason == "model_timeout_read_allowed" with input as test_input
}

# Test 6: Model CANNOT override static deny (unauthorized tool)
test_model_cannot_override_static_deny if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["list_issues", "delete_file"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["list_issues"],  # delete_file not in token
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "delete_file",
            "permission": "github:delete_file:write",
            "risk_tier": "irreversible_or_privilege"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        "session": {"tainted": false},
        "model": {"timed_out": false},
        "scores": {"intent_match": 1.0, "injection_risk": 0.0}
    }
    authz.outcome == "deny" with input as test_input
    authz.reason == "static_tool_not_granted_in_token" with input as test_input
}

# Test 7: Allow Narrower when query requests large limit (>10)
test_allow_narrower_large_limit if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["list_issues"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["list_issues"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "list_issues",
            "permission": "github:list_issues:read",
            "risk_tier": "read"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test", "limit": 100},
        "session": {"tainted": false},
        "model": {"timed_out": false},
        "scores": {"intent_match": 0.95, "sensitivity": 0.10}
    }
    authz.outcome == "allow_narrower" with input as test_input
}

# Test 8: Tainted session causes write tools to be held
test_tainted_session_holds_writes if {
    test_input := {
        "user": {"id": "u1", "roles": ["developer"], "allowed_tools": ["issue_write"]},
        "token": {
            "authorization_details": [{
                "type": "mcp_tool",
                "server": "https://api.githubcopilot.com/mcp/",
                "tools": ["issue_write"],
                "constraints": {"owner": "shreenithi23", "repo": "mcp-shield-test"}
            }]
        },
        "action": {
            "server": "https://api.githubcopilot.com/mcp/",
            "tool": "issue_write",
            "permission": "github:issue_write:write",
            "risk_tier": "reversible_write"
        },
        "arguments": {"owner": "shreenithi23", "repo": "mcp-shield-test"},
        "session": {"tainted": true},  # Session was tainted by prior tool output
        "model": {"timed_out": false},
        "scores": {"intent_match": 0.99, "injection_risk": 0.01}
    }
    authz.outcome == "hold" with input as test_input
    authz.reason == "session_tainted_write_held" with input as test_input
}
