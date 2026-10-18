"""Plain-English explanation generator for held and denied calls ONLY."""

import os
from typing import Any, Dict, Optional
import httpx


class ExplanationGenerator:
    """Generates concise 1-2 sentence human-readable explanations for blocked and held calls."""

    def __init__(self, api_key: Optional[str] = None, api_base: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.api_base = api_base or os.getenv("OPENAI_API_BASE", "https://openrouter.ai/api/v1")

    async def generate_explanation(
        self,
        outcome: str,
        reason: str,
        tool_name: str,
        arguments: Dict[str, Any],
        is_tainted: bool = False,
        risk_tier: str = "read",
    ) -> str:
        """Generates concise explanation for why a call was held or denied."""
        if outcome not in ("deny", "hold", "allow_narrower"):
            return ""

        # Deterministic zero-overhead fast-path for standard policy reasons
        if outcome == "hold" and is_tainted and risk_tier != "read":
            return (
                f"Tool '{tool_name}' was held because the session is currently tainted from a detected prompt "
                "injection payload. All write operations are paused until an administrator clears the taint."
            )

        if "high_risk_tier" in reason or risk_tier == "irreversible_or_privilege":
            return (
                f"Tool '{tool_name}' is classified as an irreversible high-risk operation and requires out-of-band "
                "human approval before modifying repository state."
            )

        if "static_tool_not_granted_in_token" in reason:
            return (
                f"Execution of tool '{tool_name}' was blocked because it is not permitted by the agent's "
                "cryptographic access token (RFC 9396 delegation boundary)."
            )

        if "static_argument_constraint_violated" in reason:
            return (
                f"Tool '{tool_name}' was blocked because the target repository arguments violated the "
                "strict boundary constraint granted in the token."
            )

        if "prompt_injection_risk_denied" in reason:
            return (
                f"Tool '{tool_name}' was blocked because the input arguments contained an adversarial prompt "
                "injection or privilege escalation pattern."
            )

        if "model_timeout_write_held" in reason:
            return (
                f"Tool '{tool_name}' was held for human approval because the decision verification model exceeded "
                "the 150ms timeout threshold, triggering fail-closed protection."
            )

        if outcome == "allow_narrower":
            return (
                f"Query parameters for '{tool_name}' were narrowed (row limit clamped to 10) to minimize blast "
                "radius and enforce least-privilege data access."
            )

        # Fallback explanation
        action_verb = "held for human approval" if outcome == "hold" else "denied"
        return f"Tool '{tool_name}' was {action_verb} by zero-trust gateway policy ({reason})."


explanation_generator = ExplanationGenerator()
