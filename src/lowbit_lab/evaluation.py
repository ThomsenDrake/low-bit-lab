from __future__ import annotations

import hashlib
import json
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
    ladder_tokens: tuple[int, ...]
    stop_on_first_failure: bool
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
    ladder_tokens: object | None = None,
    stop_on_first_failure: object = True,
) -> ContextState:
    if (
        not isinstance(configured_tokens, int)
        or isinstance(configured_tokens, bool)
        or configured_tokens <= 0
    ):
        raise ValueError("configured context tokens must be a positive integer")
    if not isinstance(runtime_initialized, bool) or not isinstance(usefulness_proven, bool):
        raise ValueError("context proof states must be boolean")
    if ladder_tokens is None:
        ladder = (configured_tokens,)
    elif (
        not isinstance(ladder_tokens, list | tuple)
        or not ladder_tokens
        or any(
            not isinstance(level, int) or isinstance(level, bool) or level <= 0
            for level in ladder_tokens
        )
    ):
        raise ValueError("context ladder must contain positive integers")
    else:
        ladder = tuple(ladder_tokens)
    if tuple(sorted(set(ladder))) != ladder or ladder[-1] != configured_tokens:
        raise ValueError("context ladder must be strictly increasing to configured tokens")
    if stop_on_first_failure is not True:
        raise ValueError("context ladder must stop on first failure")
    if usefulness_proven and not runtime_initialized:
        raise ValueError("useful context requires runtime initialization")
    if usefulness_proven and not retrieval_evidence_sha256:
        raise ValueError("useful context requires retrieval evidence")
    return ContextState(
        configured_tokens=configured_tokens,
        ladder_tokens=ladder,
        stop_on_first_failure=True,
        runtime_initialized=runtime_initialized,
        usefulness_proven=usefulness_proven,
        retrieval_evidence_sha256=retrieval_evidence_sha256,
    )


def assert_candidate_execution_allowed(lock: object) -> None:
    """Mechanically gate candidates on a full, threshold-authorized lock."""

    from lowbit_lab.evaluation_lock import FullEvaluationLock

    if not isinstance(lock, FullEvaluationLock):
        raise CandidateExecutionBlocked("candidate execution is blocked by evaluation authority")
    try:
        identity = json.loads(lock.canonical_json)
    except (json.JSONDecodeError, TypeError):
        raise CandidateExecutionBlocked(
            "candidate execution is blocked by evaluation authority"
        ) from None
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    authority = identity.get("authority")
    if (
        canonical != lock.canonical_json
        or hashlib.sha256(canonical.encode()).hexdigest() != lock.sha256
        or identity.get("base_lock_sha256") != lock.base_lock_sha256
        or not isinstance(authority, dict)
        or authority.get("authority_sha256") != lock.authority_sha256
    ):
        raise CandidateExecutionBlocked("candidate execution is blocked by evaluation authority")
    status = lock.status
    promotion_authorized = lock.promotion_authorized
    candidate_execution = lock.candidate_execution
    if not (
        status == "locked" and promotion_authorized is True and candidate_execution == "allowed"
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
