from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from lowbit_lab.constants import EVALUATION_FAMILIES
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.reference_harness import (
    ReferenceHarnessError,
    ReferenceObservation,
    run_reference_harness,
)


def _execution_identity() -> dict[str, str]:
    return {
        "weight_inventory_sha256": "1" * 64,
        "provenance_manifest_sha256": "2" * 64,
        "runtime_receipt_sha256": "3" * 64,
        "reviewed_commit_sha256": "4" * 40,
        "resource_spec_sha256": "5" * 64,
    }


METRICS = {
    "coding": ["exact_match"],
    "tool_call_validity": ["schema_valid_rate"],
    "long_context_retrieval": ["retrieval_accuracy"],
    "throughput": ["decode_tokens_per_second"],
    "memory": ["peak_vram_bytes"],
    "soak": ["failure_free_rate", "runtime_errors", "completed_minutes"],
}


def _materials() -> dict[str, bytes]:
    return {
        family: json.dumps(
            {"case_id": f"generic-{index}", "input": f"synthetic-{family}"},
            sort_keys=True,
        ).encode()
        for index, family in enumerate(EVALUATION_FAMILIES, start=1)
    }


def _raw_lock(materials: dict[str, bytes]) -> dict[str, object]:
    fixtures = []
    for index, family in enumerate(EVALUATION_FAMILIES, start=1):
        fixtures.append(
            {
                "family": family,
                "fixture_id": f"generic-{family}-fixture",
                "version": f"1.0.{index}",
                "sha256": hashlib.sha256(materials[family]).hexdigest(),
                "source": {
                    "classification": "synthetic",
                    "reference": f"generated-contract-{index}",
                    "license": "CC0-1.0",
                },
                "seed": 4100 + index,
                "scorer_id": "deterministic-json-scorer",
                "metrics": METRICS[family],
            }
        )
    return {
        "schema_version": 2,
        "suite_id": "generic-evaluation-suite",
        "suite_version": "2.0.0",
        "fixtures": fixtures,
        "fixture_order": [fixture["fixture_id"] for fixture in fixtures],
        "scorer": {
            "id": "deterministic-json-scorer",
            "version": "1.0.0",
            "sha256": "a" * 64,
            "runtime": {"id": "python", "version": "3.12", "sha256": "b" * 64},
        },
        "generation": {
            "batch_size": 1,
            "do_sample": False,
            "temperature": "0",
            "top_p": "1",
            "response_caps_tokens": {family: 128 for family in EVALUATION_FAMILIES},
            "response_caps_bytes": {family: 4096 for family in EVALUATION_FAMILIES},
        },
        "metrics": METRICS,
        "aggregation": {"method": "arithmetic_mean", "missing": "fail"},
        "confidence": {
            "method": "bootstrap_percentile",
            "level": "0.95",
            "resamples": 1000,
            "seed": 90210,
        },
        "context": {
            "configured_tokens": 32768,
            "ladder_tokens": [8192, 16384, 32768],
            "stop_on_first_failure": True,
            "runtime_initialized": False,
            "usefulness_proven": False,
            "retrieval_evidence_sha256": None,
        },
        "resources": {
            "weights_required": False,
            "allow_cloud_upload": False,
            "remote_submission_enabled": False,
            "scheduling_enabled": False,
            "destructive_cleanup_enabled": False,
            "requested_cloud_cost_usd": "0",
            "actual_cloud_cost_usd": "0",
            "max_wall_clock_seconds": 300,
            "max_ram_bytes": 1073741824,
            "max_vram_bytes": 1073741824,
        },
        "stop_policy": {
            "fixture_hash_mismatch": "stop",
            "privacy_violation": "stop",
            "scorer_drift": "stop",
            "resource_limit": "stop",
            "unknown_state": "stop",
        },
        "threshold_authority": {"status": "absent"},
        "promotion_authorized": False,
        "candidate_execution": "blocked",
    }


def _fixture_bytes(raw: dict[str, object], materials: dict[str, bytes]) -> dict[str, bytes]:
    return {
        str(fixture["fixture_id"]): materials[str(fixture["family"])] for fixture in raw["fixtures"]
    }


class DeterministicExecutor:
    def __init__(
        self,
        *,
        failed_context: int | None = None,
        scorer_sha256: str = "a" * 64,
        runtime_sha256: str = "b" * 64,
    ) -> None:
        self.failed_context = failed_context
        self.scorer_sha256 = scorer_sha256
        self.runtime_sha256 = runtime_sha256
        self.requests = []

    def identity(self) -> dict[str, str]:
        return {
            "scorer_sha256": self.scorer_sha256,
            "runtime_sha256": self.runtime_sha256,
        }

    def evaluate(self, request):
        self.requests.append(request)
        if (
            request.family == "long_context_retrieval"
            and request.context_level_tokens == self.failed_context
        ):
            return ReferenceObservation(
                status="failed", metrics={}, response=b"", generated_tokens=0
            )
        values = {metric: (0 if metric == "runtime_errors" else 1.0) for metric in request.metrics}
        return ReferenceObservation(
            status="completed", metrics=values, response=b"{}", generated_tokens=1
        )


def test_reference_manifest_is_deterministic_reference_only_and_six_family() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    first = run_reference_harness(
        lock, fixture_bytes, DeterministicExecutor(), _execution_identity()
    )
    second = run_reference_harness(
        lock, fixture_bytes, DeterministicExecutor(), _execution_identity()
    )

    assert first.sha256 == second.sha256
    assert first.canonical_json == second.canonical_json
    identity = json.loads(first.canonical_json)
    assert identity["kind"] == "reference_metrics"
    assert identity["evaluation_lock_sha256"] == lock.sha256
    assert {item["family"] for item in identity["measurements"]} == set(EVALUATION_FAMILIES)
    assert all("context_level_tokens" in item for item in identity["measurements"])
    assert "thresholds" not in first.canonical_json
    assert "candidate_execution" not in first.canonical_json


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw["scorer"].update({"sha256": "c" * 64}),
        lambda raw: raw["fixtures"][0].update({"version": "3.0.0"}),
        lambda raw: raw["generation"].update({"temperature": "0.1"}),
        lambda raw: raw["fixture_order"].reverse(),
        lambda raw: raw["context"].update({"ladder_tokens": [8192, 32768]}),
        lambda raw: raw["scorer"]["runtime"].update({"sha256": "d" * 64}),
    ],
)
def test_protocol_drift_produces_a_new_identity(mutate) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    original = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    changed_raw = copy.deepcopy(raw)
    mutate(changed_raw)
    changed = validate_pending_evaluation_lock(changed_raw, fixture_bytes=fixture_bytes)

    assert changed.sha256 != original.sha256
    assert (
        run_reference_harness(
            changed,
            fixture_bytes,
            DeterministicExecutor(
                scorer_sha256=str(changed.scorer["sha256"]),
                runtime_sha256=str(changed.scorer["runtime"]["sha256"]),
            ),
            _execution_identity(),
        ).sha256
        != run_reference_harness(
            original, fixture_bytes, DeterministicExecutor(), _execution_identity()
        ).sha256
    )


def test_fixture_content_drift_produces_a_new_manifest_identity() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    original = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    changed_raw = copy.deepcopy(raw)
    changed_bytes = dict(fixture_bytes)
    fixture_id = str(changed_raw["fixtures"][0]["fixture_id"])
    changed_bytes[fixture_id] = b'{"case_id":"generic-changed","input":"synthetic"}'
    changed_raw["fixtures"][0]["sha256"] = hashlib.sha256(changed_bytes[fixture_id]).hexdigest()
    changed = validate_pending_evaluation_lock(changed_raw, fixture_bytes=changed_bytes)

    assert (
        run_reference_harness(
            changed, changed_bytes, DeterministicExecutor(), _execution_identity()
        ).sha256
        != run_reference_harness(
            original, fixture_bytes, DeterministicExecutor(), _execution_identity()
        ).sha256
    )


def test_in_memory_lock_object_drift_blocks_reuse() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    drifted = replace(lock, fixture_order=tuple(reversed(lock.fixture_order)))

    with pytest.raises(ReferenceHarnessError, match="object drift"):
        run_reference_harness(
            drifted, fixture_bytes, DeterministicExecutor(), _execution_identity()
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_reference_metrics_fail_closed(value: float) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    class NonFiniteExecutor(DeterministicExecutor):
        def evaluate(self, request):
            observation = super().evaluate(request)
            if request.family == "coding":
                return ReferenceObservation(
                    status="completed",
                    metrics={"exact_match": value},
                    response=b"{}",
                    generated_tokens=1,
                )
            return observation

    with pytest.raises(ReferenceHarnessError, match="finite"):
        run_reference_harness(lock, fixture_bytes, NonFiniteExecutor(), _execution_identity())


def test_context_ladder_stops_after_first_failure() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    executor = DeterministicExecutor(failed_context=16384)

    result = run_reference_harness(lock, fixture_bytes, executor, _execution_identity())

    retrieval_levels = [
        request.context_level_tokens
        for request in executor.requests
        if request.family == "long_context_retrieval"
    ]
    assert retrieval_levels == [8192, 16384]
    assert result.status == "incomplete_reference"


def test_response_byte_cap_and_metric_shape_fail_closed() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    raw["generation"]["response_caps_bytes"]["coding"] = 1
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    with pytest.raises(ReferenceHarnessError, match="response byte cap"):
        run_reference_harness(lock, fixture_bytes, DeterministicExecutor(), _execution_identity())

    class MissingMetricExecutor(DeterministicExecutor):
        def evaluate(self, request):
            if request.family == "soak":
                return ReferenceObservation(
                    status="completed",
                    metrics={"failure_free_rate": 1.0},
                    response=b"{}",
                    generated_tokens=1,
                )
            return super().evaluate(request)

    raw["generation"]["response_caps_bytes"]["coding"] = 4096
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    with pytest.raises(ReferenceHarnessError, match="metric set"):
        run_reference_harness(lock, fixture_bytes, MissingMetricExecutor(), _execution_identity())


def test_response_token_cap_fails_closed() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    raw["generation"]["response_caps_tokens"]["coding"] = 1
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    class OverTokenCapExecutor(DeterministicExecutor):
        def evaluate(self, request):
            observation = super().evaluate(request)
            if request.family == "coding":
                return ReferenceObservation(
                    status="completed",
                    metrics=observation.metrics,
                    response=observation.response,
                    generated_tokens=2,
                )
            return observation

    with pytest.raises(ReferenceHarnessError, match="response token cap"):
        run_reference_harness(lock, fixture_bytes, OverTokenCapExecutor(), _execution_identity())


def test_executor_failure_is_sanitized() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    class FailingExecutor(DeterministicExecutor):
        def evaluate(self, request):
            raise RuntimeError("secret-value-must-not-escape")

    with pytest.raises(ReferenceHarnessError, match="executor failed") as caught:
        run_reference_harness(lock, fixture_bytes, FailingExecutor(), _execution_identity())
    assert "secret-value" not in str(caught.value)


def test_executor_identity_and_metric_domains_fail_closed() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    class WrongIdentityExecutor(DeterministicExecutor):
        def identity(self) -> dict[str, str]:
            return {"scorer_sha256": "f" * 64, "runtime_sha256": "b" * 64}

    with pytest.raises(ReferenceHarnessError, match="does not match"):
        run_reference_harness(lock, fixture_bytes, WrongIdentityExecutor(), _execution_identity())

    class ImpossibleRateExecutor(DeterministicExecutor):
        def evaluate(self, request):
            observation = super().evaluate(request)
            if request.family == "coding":
                return replace(observation, metrics={"exact_match": 1.1})
            return observation

    with pytest.raises(ReferenceHarnessError, match="outside"):
        run_reference_harness(lock, fixture_bytes, ImpossibleRateExecutor(), _execution_identity())


def test_precomputed_long_context_is_validated_and_not_reexecuted() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    baseline_executor = DeterministicExecutor()
    baseline = run_reference_harness(lock, fixture_bytes, baseline_executor, _execution_identity())
    precomputed = {
        request.context_level_tokens: ReferenceObservation(
            status="completed",
            metrics={"retrieval_accuracy": 1.0},
            response=b"{}",
            generated_tokens=1,
        )
        for request in baseline_executor.requests
        if request.family == "long_context_retrieval"
    }
    executor = DeterministicExecutor()

    result = run_reference_harness(
        lock,
        fixture_bytes,
        executor,
        _execution_identity(),
        precomputed_long_context=precomputed,
    )

    assert result == baseline
    assert all(request.family != "long_context_retrieval" for request in executor.requests)
    assert {request.family for request in executor.requests} == set(EVALUATION_FAMILIES) - {
        "long_context_retrieval"
    }


def test_precomputed_long_context_requires_exact_ladder_and_valid_observations() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _fixture_bytes(raw, materials)
    lock = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    observation = ReferenceObservation(
        status="completed",
        metrics={"retrieval_accuracy": 1.0},
        response=b"{}",
        generated_tokens=1,
    )
    with pytest.raises(ReferenceHarnessError, match="set drift"):
        run_reference_harness(
            lock,
            fixture_bytes,
            DeterministicExecutor(),
            _execution_identity(),
            precomputed_long_context={8192: observation},
        )
    malformed = {level: observation for level in lock.context.ladder_tokens}
    malformed[8192] = replace(observation, metrics={"exact_match": 1.0})
    with pytest.raises(ReferenceHarnessError, match="metric set"):
        run_reference_harness(
            lock,
            fixture_bytes,
            DeterministicExecutor(),
            _execution_identity(),
            precomputed_long_context=malformed,
        )
