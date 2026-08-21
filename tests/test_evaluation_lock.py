from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import lowbit_lab.evaluation_lock as evaluation_lock_module
from lowbit_lab.constants import EVALUATION_FAMILIES
from lowbit_lab.evaluation import CandidateExecutionBlocked, assert_candidate_execution_allowed
from lowbit_lab.evaluation_lock import (
    EvaluationLockError,
    apply_threshold_authority,
    validate_pending_evaluation_lock,
)

METRICS = {
    "coding": ["exact_match"],
    "tool_call_validity": ["schema_valid_rate"],
    "long_context_retrieval": ["retrieval_accuracy"],
    "throughput": ["decode_tokens_per_second"],
    "memory": ["peak_vram_bytes"],
    "soak": ["failure_free_rate"],
}


def _materials() -> dict[str, bytes]:
    return {
        family: json.dumps(
            {"case_id": f"generic-{index}", "input": f"synthetic-{family}"},
            sort_keys=True,
        ).encode()
        for index, family in enumerate(EVALUATION_FAMILIES, start=1)
    }


def _raw_lock(materials: dict[str, bytes] | None = None) -> dict[str, object]:
    materials = materials or _materials()
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
        "schema_version": 1,
        "suite_id": "generic-evaluation-suite",
        "suite_version": "1.0.0",
        "fixtures": fixtures,
        "scorer": {
            "id": "deterministic-json-scorer",
            "version": "1.0.0",
            "sha256": "a" * 64,
            "runtime": {"id": "python", "version": "3.12", "sha256": "b" * 64},
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
            "configured_tokens": 8192,
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


def _bytes_by_id(raw: dict[str, object], materials: dict[str, bytes]) -> dict[str, bytes]:
    fixtures = raw["fixtures"]
    assert isinstance(fixtures, list)
    return {
        item["fixture_id"]: materials.get(str(item["family"]), b"unknown-family")
        for item in fixtures
    }


def _extension(pending_sha256: str) -> dict[str, object]:
    extension: dict[str, object] = {
        "schema_version": 1,
        "base_lock_sha256": pending_sha256,
        "authority_id": "human-approved-threshold-contract",
        "authority_version": "1.0.0",
        "authority_sha256": "0" * 64,
        "approved_by_human": True,
        "scorer": {
            "id": "deterministic-json-scorer",
            "version": "1.0.0",
            "sha256": "a" * 64,
            "runtime": {"id": "python", "version": "3.12", "sha256": "b" * 64},
        },
        "aggregation": {"method": "arithmetic_mean", "missing": "fail"},
        "thresholds": [
            {"family": family, "metric": METRICS[family][0], "operator": "gte", "value": 0.5}
            for family in EVALUATION_FAMILIES
        ],
    }
    payload = {
        key: extension[key]
        for key in (
            "schema_version",
            "authority_id",
            "authority_version",
            "scorer",
            "aggregation",
            "thresholds",
        )
    }
    extension["authority_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return extension


def test_valid_six_family_lock_is_reproducible_and_pending() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _bytes_by_id(raw, materials)

    first = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    second = validate_pending_evaluation_lock(copy.deepcopy(raw), fixture_bytes=fixture_bytes)

    assert first.sha256 == second.sha256
    assert first.status == "pending_threshold_authority"
    assert first.promotion_authorized is False
    assert first.candidate_execution == "blocked"
    assert tuple(item.family for item in first.fixtures) == EVALUATION_FAMILIES
    with pytest.raises(CandidateExecutionBlocked):
        assert_candidate_execution_allowed(first)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw.update({"status": "placeholder_not_locked"}), "unknown keys"),
        (lambda raw: raw["fixtures"][1].update({"family": "coding"}), "families"),
        (lambda raw: raw["fixtures"][1].update({"family": "unknown"}), "families"),
        (lambda raw: raw["fixtures"][1]["source"].update({"license": ""}), "license"),
        (lambda raw: raw["fixtures"][1].pop("seed"), "missing keys"),
        (lambda raw: raw["fixtures"][1].update({"scorer_id": "drifted"}), "scorer"),
        (
            lambda raw: raw["fixtures"][1].update(
                {"fixture_id": raw["fixtures"][0]["fixture_id"]}
            ),
            "fixture_id",
        ),
        (
            lambda raw: raw["fixtures"][1].update(
                {"version": raw["fixtures"][0]["version"]}
            ),
            "version",
        ),
        (lambda raw: raw["fixtures"][1].update({"sha256": raw["fixtures"][0]["sha256"]}), "sha256"),
    ],
)
def test_invalid_lock_shapes_fail_closed(mutation, message: str) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    mutation(raw)
    with pytest.raises(EvaluationLockError, match=message):
        validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))


def test_placeholder_fixture_and_changed_bytes_are_rejected() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _bytes_by_id(raw, materials)
    fixture_bytes[raw["fixtures"][0]["fixture_id"]] = b'{"status":"placeholder_not_locked"}'
    with pytest.raises(EvaluationLockError, match="placeholder"):
        validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)

    fixture_bytes[raw["fixtures"][0]["fixture_id"]] = b'{"case":"changed"}'
    with pytest.raises(EvaluationLockError, match="hash mismatch"):
        validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)


@pytest.mark.parametrize(
    "unsafe",
    [
        b'{"token":"' + b"ghp_" + b'abcdefghijklmnopqrstuvwxyz123456"}',
        b'{"employee_id":"person-123"}',
        b'{"path":"C:\\\\' + b'Users\\\\person\\\\work.txt"}',
        b'{"path":"/mnt/c/' + b'Users/person/work.txt"}',
        b'{"path":"/ho' + b'me/person/private.txt"}',
    ],
)
def test_privacy_rejection_is_sanitized_and_precedes_hashing(monkeypatch, unsafe: bytes) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    fixture_bytes = _bytes_by_id(raw, materials)
    fixture_id = raw["fixtures"][0]["fixture_id"]
    fixture_bytes[fixture_id] = unsafe

    def forbidden_hash(_: bytes) -> str:
        raise AssertionError("hashing ran before privacy validation")

    monkeypatch.setattr(evaluation_lock_module, "_sha256_bytes", forbidden_hash)
    with pytest.raises(EvaluationLockError) as caught:
        validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    message = str(caught.value)
    assert "privacy validation failed" in message
    assert unsafe.decode(errors="ignore") not in message
    assert "person" not in message


def test_lock_metadata_privacy_gate_precedes_fixture_hashing(monkeypatch) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    raw["fixtures"][0]["source"]["reference"] = "C:\\" + "Users\\local-user\\fixture.json"

    def forbidden_hash(_: bytes) -> str:
        raise AssertionError("hashing ran before metadata privacy validation")

    monkeypatch.setattr(evaluation_lock_module, "_sha256_bytes", forbidden_hash)
    with pytest.raises(EvaluationLockError, match="privacy validation failed") as caught:
        validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))
    assert "local-user" not in str(caught.value)


@pytest.mark.parametrize("classification", ["private", "undeclared", None])
def test_private_or_undeclared_source_classification_is_rejected(classification) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    raw["fixtures"][0]["source"]["classification"] = classification
    with pytest.raises(EvaluationLockError, match="source classification"):
        validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))


def test_context_usefulness_requires_runtime_and_retrieval_evidence() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    raw["context"].update({"runtime_initialized": True, "usefulness_proven": True})
    with pytest.raises(EvaluationLockError, match="retrieval evidence"):
        validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))


def test_compatible_authority_creates_new_full_identity() -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    pending = validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))
    full = apply_threshold_authority(pending, _extension(pending.sha256))

    assert full.base_lock_sha256 == pending.sha256
    assert full.sha256 != pending.sha256
    assert full.status == "locked"
    assert full.promotion_authorized is True
    assert_candidate_execution_allowed(full)


def test_full_lock_cannot_be_constructed_or_tampered_with_directly() -> None:
    from lowbit_lab.evaluation_lock import FullEvaluationLock

    with pytest.raises(EvaluationLockError, match="threshold authority validation"):
        FullEvaluationLock(
            base_lock_sha256="1" * 64,
            authority_sha256="2" * 64,
            canonical_json="{}",
            sha256="3" * 64,
            _token=object(),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda ext: ext.update({"base_lock_sha256": "0" * 64}), "base lock"),
        (lambda ext: ext["thresholds"][0].update({"family": "unknown"}), "family"),
        (lambda ext: ext["thresholds"][0].update({"metric": "unknown"}), "metric"),
        (lambda ext: ext["scorer"].update({"version": "2.0.0"}), "scorer"),
        (lambda ext: ext["aggregation"].update({"method": "maximum"}), "aggregation"),
        (lambda ext: ext["thresholds"][0].update({"operator": "approximately"}), "operator"),
        (lambda ext: ext.update({"approved_by_human": False}), "human approval"),
        (lambda ext: ext.update({"authority_sha256": "f" * 64}), "content hash"),
    ],
)
def test_incompatible_authority_cannot_reinterpret_pending_lock(mutation, message: str) -> None:
    materials = _materials()
    raw = _raw_lock(materials)
    pending = validate_pending_evaluation_lock(raw, fixture_bytes=_bytes_by_id(raw, materials))
    extension = _extension(pending.sha256)
    mutation(extension)
    original_sha256 = pending.sha256

    with pytest.raises(EvaluationLockError, match=message):
        apply_threshold_authority(pending, extension)

    assert pending.sha256 == original_sha256
    assert pending.promotion_authorized is False
    with pytest.raises(CandidateExecutionBlocked):
        assert_candidate_execution_allowed(pending)


def test_public_example_is_closed_and_pending() -> None:
    raw = json.loads(Path("configs/evaluation-lock.example.json").read_text(encoding="utf-8"))
    assert set(raw) == {
        "schema_version",
        "suite_id",
        "suite_version",
        "fixtures",
        "scorer",
        "metrics",
        "aggregation",
        "confidence",
        "context",
        "resources",
        "stop_policy",
        "threshold_authority",
        "promotion_authorized",
        "candidate_execution",
    }
    assert raw["threshold_authority"] == {"status": "absent"}
    assert raw["promotion_authorized"] is False
    assert raw["candidate_execution"] == "blocked"
    assert "placeholder" not in json.dumps(raw).lower()
