"""Base abstractions for the AI Decision Model adapter.

Decision models return calibrated probabilities over fixed options (not free-form text)
and support batching multiple questions about a single context into one request.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Option(BaseModel):
    """A fixed option in a multiple-choice decision question."""
    id: str = Field(description="Option identifier (e.g. 'true', 'false', 'high', 'low')")
    description: str = Field(description="Option semantic meaning")
    numeric_weight: float = Field(default=1.0, description="Mapping weight between 0.0 and 1.0")


class DecisionQuestion(BaseModel):
    """A specific evaluation question evaluated by the model."""
    id: str = Field(description="Question ID, e.g. 'intent_match', 'overreach', 'injection_risk'")
    prompt: str = Field(description="The calibrated question prompt")
    options: List[Option] = Field(default_factory=list)


class CalibratedScore(BaseModel):
    """Calibrated probability score over fixed options."""
    question_id: str
    probabilities: Dict[str, float] = Field(description="Normalized probability distribution over option IDs")
    value: float = Field(description="Computed scalar score between 0.0 and 1.0")
    confidence: float = Field(default=1.0, description="Model confidence calibration")


class DecisionBatchRequest(BaseModel):
    """Batch of questions evaluated against a single shared context."""
    context: Dict[str, Any] = Field(description="Context data: task_id, tool, arguments, session state")
    questions: List[DecisionQuestion] = Field(description="Questions to evaluate concurrently in this request")


class DecisionBatchResponse(BaseModel):
    """Calibrated batch evaluation response."""
    model_name: str
    model_version: str
    scores: Dict[str, CalibratedScore] = Field(description="Map of question_id -> CalibratedScore")
    latency_ms: float
    timed_out: bool = False


class BaseDecisionModel(ABC):
    """Abstract adapter interface for calibrated decision models."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_version(self) -> str:
        pass

    @abstractmethod
    async def evaluate_batch(
        self,
        request: DecisionBatchRequest,
        timeout_ms: float = 150.0,
    ) -> DecisionBatchResponse:
        """Evaluates a batch of questions against context with strict timeout."""
        pass
