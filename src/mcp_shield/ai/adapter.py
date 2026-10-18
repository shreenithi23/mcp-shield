"""Unified Decision Model adapter factory using OpenJev."""

import os
from typing import Optional
from mcp_shield.ai.base import BaseDecisionModel
from mcp_shield.ai.openjev_provider import OpenJevProvider, OpenJevDecisionBackend


def get_decision_provider(provider_name: Optional[str] = None) -> BaseDecisionModel:
    """Returns configured OpenJev decision model provider."""
    api_base = os.getenv("OPENJEV_API_BASE")
    api_key = os.getenv("OPENJEV_API_KEY") or os.getenv("OPENROUTER_API_KEY")
    backend = OpenJevDecisionBackend(api_base=api_base, api_key=api_key)
    return OpenJevProvider(backend=backend)
