from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from lowbit_lab.constants import EVALUATION_FAMILIES
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


def validate_reference_manifest_bytes(
    content: bytes,
    *,
    evaluation_lock_sha256: str,
    context_ladder_tokens: tuple[int, ...] | None = None,
) -> ReferenceManifest:
    if not isinstance(content, bytes) or len(content) > 65_536:
        raise ReferenceHarnessError("reference manifest exceeds the response cap")
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReferenceHarnessError("reference manifest is invalid JSON") from None
    if not isinstance(raw, Mapping) or set(raw) != {
        "evaluation_lock_sha256",
        "execution_identity",
        "executor_identity",
        "kind",
        "measurements",
        "schema_version",
        "status",
    }:
        raise ReferenceHarnessError("reference manifest schema drift")
    if (
        raw["schema_version"] != 1
        or raw["kind"] != "reference_metrics"
        or raw["evaluation_lock_sha256"] != evaluation_lock_sha256
        or raw["status"] != "completed"
        or not isinstance(raw["measurements"], list)
    ):
        raise ReferenceHarnessError("reference manifest identity drift")
    validate_execution_identity(raw["execution_identity"])
    executor_identity = raw["executor_identity"]
    if (
        not isinstance(executor_identity, Mapping)
        or set(executor_identity) != {"runtime_sha256", "scorer_sha256"}
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in executor_identity.values()
        )
    ):
        raise ReferenceHarnessError("reference executor identity drift")
    families: list[str] = []
    for measurement in raw["measurements"]:
        if not isinstance(measurement, Mapping) or set(measurement) != {
            "context_level_tokens",
            "family",
            "fixture_id",
            "metrics",
            "response_bytes",
            "response_sha256",
            "response_tokens",
            "status",
        }:
            raise ReferenceHarnessError("reference manifest measurement drift")
        family = measurement["family"]
        if family not in EVALUATION_FAMILIES or measurement["status"] != "completed":
            raise ReferenceHarnessError("reference manifest measurement drift")
        context_tokens = measurement["context_level_tokens"]
        magnitudes = (measurement["response_bytes"], measurement["response_tokens"])
        if (
            not isinstance(measurement["fixture_id"], str)
            or not measurement["fixture_id"]
            or not isinstance(context_tokens, int)
            or isinstance(context_tokens, bool)
            or context_tokens <= 0
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in magnitudes
            )
        ):
            raise ReferenceHarnessError("reference manifest measurement drift")
        digest = measurement["response_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(measurement["metrics"], Mapping)
            or not measurement["metrics"]
            or any(
                not isinstance(name, str)
                or not isinstance(value, int | float)
                or isinstance(value, bool)
                or not math.isfinite(value)
                for name, value in measurement["metrics"].items()
            )
        ):
            raise ReferenceHarnessError("reference manifest measurement drift")
        families.append(str(family))
    if set(families) != set(EVALUATION_FAMILIES):
        raise ReferenceHarnessError("reference manifest family set drift")
    if any(
        families.count(family) != 1
        for family in EVALUATION_FAMILIES
        if family != "long_context_retrieval"
    ):
        raise ReferenceHarnessError("reference manifest family set drift")
    if context_ladder_tokens is not None:
        levels = tuple(
            measurement["context_level_tokens"]
            for measurement in raw["measurements"]
            if measurement["family"] == "long_context_retrieval"
        )
        if levels != context_ladder_tokens:
            raise ReferenceHarnessError("reference manifest context ladder drift")
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if content != canonical.encode():
        raise ReferenceHarnessError("reference manifest must be canonical JSON")
    return ReferenceManifest(
        status=str(raw["status"]),
        canonical_json=canonical,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def validate_execution_identity(value: object) -> dict[str, str]:
    fields = {
        "weight_inventory_sha256",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "reviewed_commit_sha256",
        "resource_spec_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReferenceHarnessError("reference execution identity is incomplete")
    result: dict[str, str] = {}
    for name, digest in value.items():
        expected_length = 40 if name == "reviewed_commit_sha256" else 64
        if (
            not isinstance(digest, str)
            or len(digest) != expected_length
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ReferenceHarnessError("reference execution identity is invalid")
        result[name] = digest
    return dict(sorted(result.items()))


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
    *,
    precomputed_long_context: Mapping[int, ReferenceObservation] | None = None,
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
    bound_execution_identity = validate_execution_identity(execution_identity)
    fixtures = {fixture.fixture_id: fixture for fixture in lock.fixtures}
    generation = lock.generation
    generation_json = json.dumps(
        generation, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    token_caps = generation["response_caps_tokens"]
    byte_caps = generation["response_caps_bytes"]
    measurements: list[dict[str, object]] = []
    complete = True
    if precomputed_long_context is not None and (
        not isinstance(precomputed_long_context, Mapping)
        or set(precomputed_long_context) != set(lock.context.ladder_tokens)
        or any(
            not isinstance(level, int) or isinstance(level, bool)
            for level in precomputed_long_context
        )
    ):
        raise ReferenceHarnessError("precomputed long-context set drift")

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
            if fixture.family == "long_context_retrieval" and precomputed_long_context is not None:
                raw_observation = precomputed_long_context[context_level]
            else:
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
        "execution_identity": bound_execution_identity,
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
