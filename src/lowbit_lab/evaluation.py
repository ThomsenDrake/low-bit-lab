from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from lowbit_lab.constants import EVALUATION_FAMILIES


@dataclass(frozen=True)
class EvaluationRequest:
    fixture_path: Path
    seed: int
    configured_context_tokens: int


@dataclass(frozen=True)
class EvaluationResult:
    family: str
    status: str
    metrics: dict[str, Any]
    useful_context_proven: bool = False


class Evaluator(Protocol):
    family: str

    def run(self, request: EvaluationRequest) -> EvaluationResult: ...


def placeholder_result(family: str) -> EvaluationResult:
    if family not in EVALUATION_FAMILIES:
        raise ValueError(f"unknown evaluation family: {family}")
    return EvaluationResult(
        family=family,
        status="placeholder_not_executed",
        metrics={},
        useful_context_proven=False,
    )
