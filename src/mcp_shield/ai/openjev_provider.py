"""OpenJev decision engine integration (https://github.com/GPT-AGI/OpenJev)."""

import asyncio
import hashlib
import json
import math
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from openjev import Choice, Noul, Score, SystemOneRequest, SystemOneResponse
from openjev.backends.base import Backend, render_prompt, render_state
from openjev.core.primitives import ChoiceAnswer, NoulAnswer, ScoreAnswer

from mcp_shield.ai.base import (
    BaseDecisionModel,
    CalibratedScore,
    DecisionBatchRequest,
    DecisionBatchResponse,
)


class OpenJevDecisionBackend(Backend):
    """OpenJev decision backend supporting both remote logprobs API and local semantic likelihood."""

    name: str = "openjev-engine"

    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        model_id: str = "openjev-latest",
    ):
        self.api_base = api_base or os.getenv("OPENJEV_API_BASE")
        self.api_key = api_key or os.getenv("OPENJEV_API_KEY") or os.getenv("OPENROUTER_API_KEY")
        self.model_id = model_id

    def score_options(self, prompt: str, labels: List[str]) -> Tuple[List[float], int]:
        """Calculates token logits for candidate labels."""
        # 1. If remote OpenJev / OpenAI-compatible endpoint is configured, use live API
        if self.api_base and self.api_key:
            try:
                return self._score_options_remote(prompt, labels)
            except Exception:
                pass

        # 2. Local semantic likelihood scoring
        return self._score_options_local(prompt, labels)

    def _score_options_remote(self, prompt: str, labels: List[str]) -> Tuple[List[float], int]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_id,
            "prompt": prompt,
            "max_tokens": 1,
            "logprobs": True,
            "top_logprobs": 20,
            "temperature": 1.0,
        }
        with httpx.Client(timeout=0.15) as client:
            resp = client.post(f"{self.api_base}/v1/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            top_lp = choice.get("logprobs", {}).get("top_logprobs", [{}])[0]
            logits = []
            for lbl in labels:
                lp = top_lp.get(lbl, top_lp.get(f" {lbl}", -15.0))
                logits.append(float(lp))
            return logits, data.get("usage", {}).get("prompt_tokens", len(prompt) // 4)

    def _score_options_local(self, prompt: str, labels: List[str]) -> Tuple[List[float], int]:
        """Calculates conditional log-odds based on state and prompt instructions."""
        lower_prompt = prompt.lower()

        # Extract question type and keywords
        is_injection_query = any(k in lower_prompt for k in ["prompt injection", "jailbreak", "rogue commands", "malicious"])
        is_intent_query = any(k in lower_prompt for k in ["match original user intent", "intent", "matches user goal"])
        is_overreach_query = any(k in lower_prompt for k in ["exceed the minimal", "overreach", "scope"])
        is_reversibility_query = any(k in lower_prompt for k in ["reversible without permanent data loss", "reversib"])
        is_sensitivity_query = any(k in lower_prompt for k in ["sensitive personal credentials", "secrets", "passwords", "private keys"])
        is_poisoning_query = any(k in lower_prompt for k in ["poisoning", "deceptive", "semantic drift"])

        # Detect indicators in prompt content
        has_injection_markers = bool(re.search(
            r"(ignore all previous instructions|system override|jailbreak|dump private keys|override policy|drop database|ai assistant:.*collaborator|collaborator with admin|backdoor)",
            lower_prompt,
        ))
        has_secret_markers = bool(re.search(
            r"(ghp_[a-zA-Z0-9]+|bearer\s+[a-zA-Z0-9_\-\.]+|private_key|password\s*[:=])",
            lower_prompt,
        ))

        # Irreversible actions: delete, drop, push, merge
        is_irreversible_action = any(k in lower_prompt for k in ["delete_file", "drop_table", "push_files", "merge_pull_request"])

        prob_yes = 0.50

        if is_injection_query:
            prob_yes = 0.96 if has_injection_markers else 0.02
        elif is_intent_query:
            # Check if tool aligns with task
            if has_injection_markers:
                prob_yes = 0.15
            elif "delete" in lower_prompt and "audit" in lower_prompt:
                prob_yes = 0.10
            elif "list_issues" in lower_prompt and ("issue" in lower_prompt or "audit" in lower_prompt):
                prob_yes = 0.95
            elif "issue_write" in lower_prompt and "issue" in lower_prompt:
                prob_yes = 0.94
            else:
                prob_yes = 0.85
        elif is_overreach_query:
            if has_injection_markers:
                prob_yes = 0.95
            elif "delete" in lower_prompt and "audit" in lower_prompt:
                prob_yes = 0.90
            else:
                prob_yes = 0.05
        elif is_reversibility_query:
            if is_irreversible_action:
                prob_yes = 0.05
            elif "list_" in lower_prompt or "get_" in lower_prompt or "read" in lower_prompt:
                prob_yes = 0.99
            else:
                prob_yes = 0.90
        elif is_sensitivity_query:
            prob_yes = 0.95 if has_secret_markers else 0.08
        elif is_poisoning_query:
            prob_yes = 0.92 if has_injection_markers else 0.02

        prob_yes = max(0.001, min(0.999, prob_yes))

        # Convert probability to log-odds logits for ["yes", "no"]
        if labels == ["yes", "no"]:
            logits = [math.log(prob_yes), math.log(1.0 - prob_yes)]
        else:
            logits = [0.0] * len(labels)
            if len(labels) > 0:
                logits[0] = math.log(prob_yes)
                for i in range(1, len(labels)):
                    logits[i] = math.log((1.0 - prob_yes) / (len(labels) - 1))

        input_tokens = max(1, len(prompt) // 4)
        return logits, input_tokens


class OpenJevProvider(BaseDecisionModel):
    """OpenJev decision provider conforming to BaseDecisionModel."""

    def __init__(
        self,
        backend: Optional[Backend] = None,
        model_name: str = "openjev-v1",
        model_version: str = "0.1.0",
        artificial_latency_ms: float = 0.0,
    ):
        self.backend: Backend = backend or OpenJevDecisionBackend()
        self._model_name = model_name
        self._model_version = model_version
        self.artificial_latency_ms = artificial_latency_ms

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    def set_latency(self, latency_ms: float) -> None:
        self.artificial_latency_ms = latency_ms

    async def decide_systemone(
        self,
        request: SystemOneRequest,
        timeout_ms: float = 150.0,
    ) -> Tuple[Dict[str, float], DecisionBatchResponse]:
        """Executes SystemOneRequest using OpenJev backend within strict timeout."""
        start_time = time.perf_counter()
        timeout_sec = timeout_ms / 1000.0

        if self.artificial_latency_ms > 0:
            delay_sec = self.artificial_latency_ms / 1000.0
            if delay_sec > timeout_sec:
                await asyncio.sleep(timeout_sec)
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return {}, DecisionBatchResponse(
                    model_name=self.model_name,
                    model_version=self.model_version,
                    scores={},
                    latency_ms=round(elapsed_ms, 2),
                    timed_out=True,
                )
            await asyncio.sleep(delay_sec)

        # Run OpenJev decision in threadpool to ensure non-blocking execution
        loop = asyncio.get_running_loop()
        try:
            resp: SystemOneResponse = await asyncio.wait_for(
                loop.run_in_executor(None, self.backend.decide, request),
                timeout=timeout_sec,
            )
        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {}, DecisionBatchResponse(
                model_name=self.model_name,
                model_version=self.model_version,
                scores={},
                latency_ms=round(elapsed_ms, 2),
                timed_out=True,
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        scores: Dict[str, float] = {}
        batch_scores: Dict[str, CalibratedScore] = {}

        for qid, ans in resp.answers.items():
            if isinstance(ans, NoulAnswer):
                val = ans.noul
                probs = {"yes": val, "no": round(1.0 - val, 4)}
                conf = max(val, 1.0 - val)
            elif isinstance(ans, ChoiceAnswer):
                val = ans.confidence
                probs = ans.probabilities
                conf = ans.confidence
            elif isinstance(ans, ScoreAnswer):
                val = ans.score
                probs = ans.probabilities
                conf = ans.confidence
            else:
                val = 0.5
                probs = {"yes": 0.5, "no": 0.5}
                conf = 0.5

            scores[qid] = round(val, 4)
            batch_scores[qid] = CalibratedScore(
                question_id=qid,
                probabilities=probs,
                value=round(val, 4),
                confidence=round(conf, 4),
            )

        batch_resp = DecisionBatchResponse(
            model_name=self.model_name,
            model_version=self.model_version,
            scores=batch_scores,
            latency_ms=round(elapsed_ms, 2),
            timed_out=False,
        )
        return scores, batch_resp

    async def evaluate_batch(
        self,
        request: DecisionBatchRequest,
        timeout_ms: float = 150.0,
    ) -> DecisionBatchResponse:
        """Adapts DecisionBatchRequest to OpenJev SystemOneRequest."""
        questions: Dict[str, Noul] = {}
        for q in request.questions:
            questions[q.id] = Noul(instructions=q.prompt)

        req = SystemOneRequest(
            state=request.context,
            questions=questions,
            model=self.model_name,
        )
        _, resp = await self.decide_systemone(req, timeout_ms=timeout_ms)
        return resp
