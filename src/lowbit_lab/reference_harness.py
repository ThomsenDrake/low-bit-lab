from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from lowbit_lab.evaluation_lock import (
    EvaluationLockError,
    PendingEvaluationLock,
    validate_pending_evaluation_lock,
)


class ReferenceHarnessError(ValueError):
    """Raised when reference evidence does not satisfy the frozen protocol."""


@dataclass(frozen=True)
class ReferenceRequest:
    family: str
    fixture_id: str
    fixture_bytes: bytes
    seed: int
    metrics: tuple[str, ...]
    context_level_tokens: int
    generation_json: str
    response_cap_tokens: int
    response_cap_bytes: int


@dataclass(frozen=True)
class ReferenceObservation:
    status: str
    metrics: Mapping[str, int | float]
    response: bytes
    generated_tokens: int


class ReferenceExecutor(Protocol):
    def identity(self) -> Mapping[str, str]: ...

    def evaluate(self, request: ReferenceRequest) -> ReferenceObservation: ...


@dataclass(frozen=True)
class ReferenceManifest:
    status: str
    canonical_json: str
    sha256: str


def _validate_lock_identity(lock: PendingEvaluationLock) -> dict[str, object]:
    try:
        raw = json.loads(lock.canonical_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ReferenceHarnessError("evaluation lock canonical identity is invalid") from exc
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if (
        canonical != lock.canonical_json
        or hashlib.sha256(canonical.encode()).hexdigest() != lock.sha256
    ):
        raise ReferenceHarnessError("evaluation lock identity drift")
    return raw


def _validated_observation(
    observation: object,
    *,
    expected_metrics: tuple[str, ...],
    response_cap_tokens: int,
    response_cap_bytes: int,
) -> ReferenceObservation:
    if not isinstance(observation, ReferenceObservation):
        raise ReferenceHarnessError("executor returned an unknown observation")
    if observation.status not in {"completed", "failed"}:
        raise ReferenceHarnessError("observation status is unknown")
    if not isinstance(observation.response, bytes):
        raise ReferenceHarnessError("reference response must be bytes")
    if len(observation.response) > response_cap_bytes:
        raise ReferenceHarnessError("reference response exceeded response byte cap")
    if (
        not isinstance(observation.generated_tokens, int)
        or isinstance(observation.generated_tokens, bool)
        or observation.generated_tokens < 0
        or observation.generated_tokens > response_cap_tokens
    ):
        raise ReferenceHarnessError("reference response exceeded response token cap")
    if observation.status == "failed":
        if observation.metrics or observation.response or observation.generated_tokens:
            raise ReferenceHarnessError("failed observation cannot contain result material")
        return observation
    if set(observation.metrics) != set(expected_metrics):
        raise ReferenceHarnessError("reference metric set drift")
    for value in observation.metrics.values():
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise ReferenceHarnessError("reference metrics must be finite numbers")
    rate_metrics = {
        "exact_match",
        "pass_rate",
        "schema_valid_rate",
        "argument_accuracy",
        "retrieval_accuracy",
        "failure_free_rate",
    }
    for name, value in observation.metrics.items():
        if name in rate_metrics and not 0 <= value <= 1:
            raise ReferenceHarnessError("reference rate metric is outside [0, 1]")
        if name == "runtime_errors" and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            raise ReferenceHarnessError("runtime_errors must be a non-negative integer")
        if name not in rate_metrics | {"runtime_errors"} and value < 0:
            raise ReferenceHarnessError("reference magnitude metric cannot be negative")
    return observation


def run_reference_harness(
    lock: PendingEvaluationLock,
    fixture_bytes: Mapping[str, bytes],
    executor: ReferenceExecutor,
    execution_identity: Mapping[str, str],
) -> ReferenceManifest:
    """Run the deterministic suite and emit reference evidence without promotion behavior."""

    if not isinstance(lock, PendingEvaluationLock):
        raise ReferenceHarnessError("reference harness requires a pending evaluation lock")
    raw = _validate_lock_identity(lock)
    try:
        validated_lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    except EvaluationLockError:
        raise ReferenceHarnessError("evaluation lock validation failed") from None
    if validated_lock != lock:
        raise ReferenceHarnessError("evaluation lock object drift")
    expected_executor_identity = {
        "scorer_sha256": str(lock.scorer["sha256"]),
        "runtime_sha256": str(lock.scorer["runtime"]["sha256"]),
    }
    try:
        executor_identity = dict(executor.identity())
    except (AttributeError, TypeError, ValueError):
        raise ReferenceHarnessError("reference executor identity is missing") from None
    if executor_identity != expected_executor_identity:
        raise ReferenceHarnessError("reference executor identity does not match the lock")
    identity_fields = {
        "weight_inventory_sha256",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "reviewed_commit_sha256",
        "resource_spec_sha256",
    }
    if not isinstance(execution_identity, Mapping) or set(execution_identity) != identity_fields:
        raise ReferenceHarnessError("reference execution identity is incomplete")
    for name, digest in execution_identity.items():
        expected_length = 40 if name == "reviewed_commit_sha256" else 64
        if (
            not isinstance(digest, str)
            or len(digest) != expected_length
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ReferenceHarnessError("reference execution identity is invalid")
    fixtures = {fixture.fixture_id: fixture for fixture in lock.fixtures}
    generation = lock.generation
    generation_json = json.dumps(
        generation, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    token_caps = generation["response_caps_tokens"]
    byte_caps = generation["response_caps_bytes"]
    measurements: list[dict[str, object]] = []
    complete = True

    for fixture_id in lock.fixture_order:
        fixture = fixtures[fixture_id]
        levels = (
            lock.context.ladder_tokens
            if fixture.family == "long_context_retrieval"
            else (lock.context.configured_tokens,)
        )
        for context_level in levels:
            request = ReferenceRequest(
                family=fixture.family,
                fixture_id=fixture.fixture_id,
                fixture_bytes=fixture_bytes[fixture.fixture_id],
                seed=fixture.seed,
                metrics=fixture.metrics,
                context_level_tokens=context_level,
                generation_json=generation_json,
                response_cap_tokens=token_caps[fixture.family],
                response_cap_bytes=byte_caps[fixture.family],
            )
            try:
                raw_observation = executor.evaluate(request)
            except Exception:
                raise ReferenceHarnessError("reference executor failed") from None
            observation = _validated_observation(
                raw_observation,
                expected_metrics=fixture.metrics,
                response_cap_tokens=request.response_cap_tokens,
                response_cap_bytes=request.response_cap_bytes,
            )
            measurement = {
                "context_level_tokens": context_level,
                "family": fixture.family,
                "fixture_id": fixture.fixture_id,
                "metrics": dict(sorted(observation.metrics.items())),
                "response_bytes": len(observation.response),
                "response_sha256": hashlib.sha256(observation.response).hexdigest(),
                "response_tokens": observation.generated_tokens,
                "status": observation.status,
            }
            measurements.append(measurement)
            if observation.status == "failed":
                complete = False
                if fixture.family != "long_context_retrieval":
                    raise ReferenceHarnessError("non-context reference family failed")
                break

    identity = {
        "evaluation_lock_sha256": lock.sha256,
        "execution_identity": dict(sorted(execution_identity.items())),
        "executor_identity": dict(sorted(executor_identity.items())),
        "kind": "reference_metrics",
        "measurements": measurements,
        "schema_version": 1,
        "status": "completed" if complete else "incomplete_reference",
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return ReferenceManifest(
        status=str(identity["status"]),
        canonical_json=canonical,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )
