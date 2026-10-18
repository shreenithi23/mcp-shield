"""OPA / Rego policy evaluator adapter."""

import fnmatch
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _eval_in_process_fallback(input_doc: Dict[str, Any]) -> Tuple[str, bool, str]:
    """In-process Python fallback implementing identical logic to authz.rego."""
    user = input_doc.get("user", {})
    user_roles = user.get("roles", [])
    allowed_tools = user.get("allowed_tools", [])
    
    action = input_doc.get("action", {})
    action_server = action.get("server")
    action_tool = action.get("tool")
    action_perm = action.get("permission", "")
    risk_tier = action.get("risk_tier")
    arguments = input_doc.get("arguments", {})

    token = input_doc.get("token", {})
    auth_details = token.get("authorization_details", [])

    session = input_doc.get("session", {})
    is_tainted = session.get("tainted", False)

    model = input_doc.get("model", {})
    timed_out = model.get("timed_out", False)

    scores = input_doc.get("scores", {})
    intent_match = scores.get("intent_match", 1.0)
    injection_risk = scores.get("injection_risk", 0.0)
    overreach = scores.get("overreach", 0.0)
    sensitivity = scores.get("sensitivity", 0.0)

    # 1. User holds permission check
    user_holds = "admin" in user_roles or action_tool in allowed_tools
    if not user_holds:
        return "deny", False, "static_user_lacks_delegation_authority"

    # 2. Token grants tool check
    matching_detail = None
    for detail in auth_details:
        if detail.get("type") == "mcp_tool" and detail.get("server") == action_server:
            if action_tool in detail.get("tools", []):
                matching_detail = detail
                break

    if not matching_detail:
        return "deny", False, "static_tool_not_granted_in_token"

    # 3. Argument constraints
    constraints = matching_detail.get("constraints", {})
    if action_perm.startswith("github:"):
        expected_owner = constraints.get("owner")
        expected_repo = constraints.get("repo")
        if expected_owner and arguments.get("owner") != expected_owner:
            return "deny", False, "static_argument_constraint_violated"
        if expected_repo and arguments.get("repo") != expected_repo:
            return "deny", False, "static_argument_constraint_violated"

    elif action_perm.startswith("slack:"):
        pattern = constraints.get("channel_pattern")
        channel = arguments.get("channel", "")
        if pattern and not fnmatch.fnmatch(channel, pattern):
            return "deny", False, "static_argument_constraint_violated"

    # Backward-compatibility fallback: static-only requests without risk tier
    if not risk_tier:
        return "allow", True, "ok"

    # 4. Irreversible or privilege-changing tier 3 tools ALWAYS hold for approval
    if risk_tier == "irreversible_or_privilege":
        return "hold", False, "high_risk_tier_requires_human_approval"

    # 5. Model timeout fail-safe (150ms timeout)
    if timed_out:
        if risk_tier == "read":
            return "allow", True, "model_timeout_read_allowed"
        else:
            return "hold", False, "model_timeout_write_held"

    # 6. Hard denies from scores
    if intent_match < 0.50:
        return "deny", False, "intent_mismatch_denied"
    if injection_risk > 0.50:
        return "deny", False, "prompt_injection_risk_denied"

    # 7. Tainted session holds writes
    if is_tainted and risk_tier != "read":
        return "hold", False, "session_tainted_write_held"

    # 8. Reversible write tier
    if risk_tier == "reversible_write":
        if intent_match >= 0.90 and injection_risk <= 0.10 and not is_tainted and overreach <= 0.20:
            return "allow", True, "ok"
        elif 0.70 <= intent_match < 0.90:
            return "hold", False, "borderline_intent_held_for_approval"
        else:
            return "hold", False, "policy_denied"

    # 9. Read tier
    if risk_tier == "read":
        limit = arguments.get("limit")
        if limit is not None and isinstance(limit, (int, float)) and limit > 10:
            return "allow_narrower", True, "narrowed_query_limit_applied"
        if sensitivity > 0.80:
            return "allow_narrower", True, "narrowed_query_limit_applied"
        if intent_match >= 0.70 and sensitivity <= 0.80:
            return "allow", True, "ok"

    return "allow", True, "ok"


class OPAEvaluator:
    """Evaluates Layer 2 PBAC and Layer 4 ABAC policies using OPA CLI with resilient in-process fallback."""

    def __init__(self, policy_path: Optional[str] = None):
        default_path = Path(__file__).parent / "authz.rego"
        self.policy_path = policy_path or str(default_path)
        self.opa_bin = shutil.which("opa")

    def evaluate(self, input_doc: Dict[str, Any]) -> Tuple[str, bool, str]:
        """Evaluates policy against input document.
        
        Returns:
            (outcome: str, allow: bool, reason: str)
            outcome is one of: "allow", "allow_narrower", "hold", "deny"
            allow is True if outcome in ("allow", "allow_narrower") else False
            reason is structured string identifier
        """
        if not self.opa_bin or not os.path.exists(self.policy_path):
            return _eval_in_process_fallback(input_doc)

        cmd = [
            self.opa_bin,
            "eval",
            "--data",
            self.policy_path,
            "--stdin-input",
            "data.mcp_shield.authz",
            "--format",
            "json",
        ]
        try:
            input_bytes = json.dumps(input_doc).encode("utf-8")
            res = subprocess.run(
                cmd,
                input=input_bytes,
                capture_output=True,
                timeout=5.0,
                check=True,
            )
            data = json.loads(res.stdout.decode("utf-8"))
            result = data.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
            outcome = result.get("outcome", "deny")
            allow = result.get("allow", False)
            reason = result.get("reason", "unknown")
            return outcome, allow, reason
        except Exception:
            return _eval_in_process_fallback(input_doc)


opa_evaluator = OPAEvaluator()
