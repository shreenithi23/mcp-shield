package mcp_shield.authz

import future.keywords.in
import future.keywords.if

# -------------------------------------------------------------
# Static PBAC Rules (The foundation: Model NEVER overrides static deny)
# -------------------------------------------------------------

# Rule: Users can only delegate permissions they themselves hold
user_holds_permission if {
    "admin" in input.user.roles
}

user_holds_permission if {
    input.action.tool in input.user.allowed_tools
}

# Rule: Token must explicitly grant the tool via RFC 9396 authorization_details
token_grants_tool if {
    some detail in input.token.authorization_details
    detail.type == "mcp_tool"
    detail.server == input.action.server
    input.action.tool in detail.tools
}

# Rule: Argument constraints validation
# 1. GitHub scoped repository constraint
satisfies_argument_constraints if {
    startswith(input.action.permission, "github:")
    some detail in input.token.authorization_details
    detail.server == input.action.server
    input.arguments.owner == detail.constraints.owner
    input.arguments.repo == detail.constraints.repo
}

# 2. Slack channel pattern constraint
satisfies_argument_constraints if {
    startswith(input.action.permission, "slack:")
    some detail in input.token.authorization_details
    detail.server == input.action.server
    glob.match(detail.constraints.channel_pattern, [], input.arguments.channel)
}

# 3. Default pass for tools without specific constraints
satisfies_argument_constraints if {
    some detail in input.token.authorization_details
    detail.server == input.action.server
    not detail.constraints.owner
    not detail.constraints.channel_pattern
}

# Combined static authorization check
static_allow if {
    user_holds_permission
    token_grants_tool
    satisfies_argument_constraints
}

# Backward-compatibility alias
allow if {
    outcome in ["allow", "allow_narrower"]
}

# -------------------------------------------------------------
# Layer 4 ABAC: Four Outcomes Resolution (Allow, Allow Narrower, Hold, Deny)
# -------------------------------------------------------------

# Default outcome fails closed to deny
default outcome := "deny"

# 1. HARD DENY: If static authorization fails, ALWAYS DENY (Model never overrides static deny)
outcome := "deny" if {
    not static_allow
}

# 1a. Static-only fallback (for requests without risk_tier / AI layer)
outcome := "allow" if {
    static_allow
    not input.action.risk_tier
}

# 1b. HARD DENY: Severe intent mismatch or high prompt injection risk
outcome := "deny" if {
    static_allow
    input.scores.intent_match < 0.50
}

outcome := "deny" if {
    static_allow
    input.scores.injection_risk > 0.50
}

# 2. HIGH-RISK TIER 3: Irreversible or privilege-changing tools ALWAYS HOLD for approval
outcome := "hold" if {
    static_allow
    input.action.risk_tier == "irreversible_or_privilege"
}

# 3. TIMEOUT FAIL-SAFE: 150ms model timeout handling
outcome := "allow" if {
    static_allow
    input.model.timed_out == true
    input.action.risk_tier == "read"
}

outcome := "hold" if {
    static_allow
    input.model.timed_out == true
    input.action.risk_tier != "read"
}

# 4. TIER 2: Reversible Write Rules
# Auto-allow if: intent_match >= 0.90 AND injection_risk <= 0.10 AND session not tainted AND overreach <= 0.20
outcome := "allow" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "reversible_write"
    input.session.tainted == false
    input.scores.intent_match >= 0.90
    input.scores.overreach <= 0.20
    input.scores.injection_risk <= 0.10
}

# Hold write for approval if session is tainted, or scores are borderline (0.70 <= intent_match < 0.90)
outcome := "hold" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "reversible_write"
    input.session.tainted == true
}

outcome := "hold" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "reversible_write"
    input.scores.intent_match >= 0.70
    input.scores.intent_match < 0.90
}

has_excessive_limit if {
    input.arguments.limit > 10
}

has_excessive_sensitivity if {
    input.scores.sensitivity > 0.80
}

# 5. TIER 1: Read-Only Rules
# Auto-allow if intent_match >= 0.70 AND sensitivity <= 0.80 (or sensitivity not present)
outcome := "allow" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "read"
    input.scores.intent_match >= 0.70
    not has_excessive_limit
    not has_excessive_sensitivity
}

# Allow narrower: Paginate / limit rows if reading with high record request or sensitive data
outcome := "allow_narrower" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "read"
    input.scores.intent_match >= 0.70
    has_excessive_limit
}

outcome := "allow_narrower" if {
    static_allow
    not input.model.timed_out
    input.action.risk_tier == "read"
    input.scores.intent_match >= 0.70
    has_excessive_sensitivity
}

# -------------------------------------------------------------
# Structured Reason Codes
# -------------------------------------------------------------
reason := "static_user_lacks_delegation_authority" if {
    not user_holds_permission
} else := "static_tool_not_granted_in_token" if {
    not token_grants_tool
} else := "static_argument_constraint_violated" if {
    not satisfies_argument_constraints
} else := "high_risk_tier_requires_human_approval" if {
    static_allow
    input.action.risk_tier == "irreversible_or_privilege"
} else := "model_timeout_write_held" if {
    static_allow
    input.model.timed_out == true
    input.action.risk_tier != "read"
} else := "model_timeout_read_allowed" if {
    static_allow
    input.model.timed_out == true
    input.action.risk_tier == "read"
} else := "session_tainted_write_held" if {
    static_allow
    input.session.tainted == true
    input.action.risk_tier == "reversible_write"
} else := "borderline_intent_held_for_approval" if {
    static_allow
    input.action.risk_tier == "reversible_write"
    input.scores.intent_match < 0.90
    input.scores.intent_match >= 0.70
} else := "intent_mismatch_denied" if {
    static_allow
    input.scores.intent_match < 0.50
} else := "prompt_injection_risk_denied" if {
    static_allow
    input.scores.injection_risk > 0.50
} else := "narrowed_query_limit_applied" if {
    outcome == "allow_narrower"
} else := "ok" if {
    outcome == "allow"
} else := "policy_denied"
