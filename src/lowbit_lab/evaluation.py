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
class ContextState:
    configured_tokens: int
    runtime_initialized: bool
    usefulness_proven: bool
    retrieval_evidence_sha256: str | None


@dataclass(frozen=True)
class EvaluationResult:
    family: str
    status: str
    metrics: dict[str, Any]
    useful_context_proven: bool = False
    retrieval_evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.family not in EVALUATION_FAMILIES:
            raise ValueError("unknown evaluation family")
        if self.useful_context_proven and not self.retrieval_evidence_sha256:
            raise ValueError("useful context requires retrieval evidence")


class Evaluator(Protocol):
    family: str

    def run(self, request: EvaluationRequest) -> EvaluationResult: ...


class CandidateExecutionBlocked(RuntimeError):
    """Raised when an evaluation lock has not authorized candidate execution."""


def validate_context_state(
    *,
    configured_tokens: int,
    runtime_initialized: bool,
    usefulness_proven: bool,
    retrieval_evidence_sha256: str | None,
) -> ContextState:
    if (
        not isinstance(configured_tokens, int)
        or isinstance(configured_tokens, bool)
        or configured_tokens <= 0
    ):
        raise ValueError("configured context tokens must be a positive integer")
    if not isinstance(runtime_initialized, bool) or not isinstance(usefulness_proven, bool):
        raise ValueError("context proof states must be boolean")
    if usefulness_proven and not runtime_initialized:
        raise ValueError("useful context requires runtime initialization")
    if usefulness_proven and not retrieval_evidence_sha256:
        raise ValueError("useful context requires retrieval evidence")
    return ContextState(
        configured_tokens=configured_tokens,
        runtime_initialized=runtime_initialized,
        usefulness_proven=usefulness_proven,
        retrieval_evidence_sha256=retrieval_evidence_sha256,
    )


def assert_candidate_execution_allowed(lock: object) -> None:
    """Mechanically gate candidates on a full, threshold-authorized lock."""

    from lowbit_lab.evaluation_lock import FullEvaluationLock

    if not isinstance(lock, FullEvaluationLock):
        raise CandidateExecutionBlocked("candidate execution is blocked by evaluation authority")
    status = lock.status
    promotion_authorized = lock.promotion_authorized
    candidate_execution = lock.candidate_execution
    if not (
        status == "locked"
        and promotion_authorized is True
        and candidate_execution == "allowed"
    ):
        raise CandidateExecutionBlocked("candidate execution is blocked by evaluation authority")


def placeholder_result(family: str) -> EvaluationResult:
    if family not in EVALUATION_FAMILIES:
        raise ValueError(f"unknown evaluation family: {family}")
    return EvaluationResult(
        family=family,
        status="placeholder_not_executed",
        metrics={},
        useful_context_proven=False,
    )
