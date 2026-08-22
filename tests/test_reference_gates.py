from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from lowbit_lab.reference_gates import (
    ReferenceGateError,
    verify_cold_path_time_evidence,
    verify_memory_fit_evidence,
    verify_provider_safety_evidence,
)


def _write(path: Path, value: object) -> str:
    content = (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def test_memory_fit_is_arithmetic_and_inventory_bound(tmp_path: Path) -> None:
    inventory = "a" * 64
    evidence = {
        "schema_version": 1,
        "kind": "memory_fit_evidence",
        "inventory_sha256": inventory,
        "evaluation_lock_sha256": "d" * 64,
        "maximum_context_tokens": 32768,
        "tensor_bytes": 55,
        "runtime_overhead_bytes": 10,
        "kv_cache_bytes": 20,
        "allocator_reserve_bytes": 5,
        "usable_gpu_memory_bytes": 89,
        "method_sha256": "b" * 64,
    }
    path = tmp_path / "memory.json"
    digest = _write(path, evidence)
    result = verify_memory_fit_evidence(
        path,
        expected_sha256=digest,
        expected_inventory_sha256=inventory,
        expected_tensor_bytes=55,
        expected_method_sha256="b" * 64,
        expected_evaluation_lock_sha256="d" * 64,
        expected_maximum_context_tokens=32768,
    )
    assert result.proven is False
    assert result.required == 90
    evidence["usable_gpu_memory_bytes"] = 90
    digest = _write(path, evidence)
    assert verify_memory_fit_evidence(
        path,
        expected_sha256=digest,
        expected_inventory_sha256=inventory,
        expected_tensor_bytes=55,
        expected_method_sha256="b" * 64,
        expected_evaluation_lock_sha256="d" * 64,
        expected_maximum_context_tokens=32768,
    ).proven


def test_memory_fit_rejects_drift_and_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "memory.json"
    digest = _write(path, {"schema_version": 1})
    with pytest.raises(ReferenceGateError, match="closed"):
        verify_memory_fit_evidence(
            path,
            expected_sha256=digest,
            expected_inventory_sha256="a" * 64,
            expected_tensor_bytes=1,
            expected_method_sha256="b" * 64,
            expected_evaluation_lock_sha256="d" * 64,
            expected_maximum_context_tokens=32768,
        )
    with pytest.raises(ReferenceGateError, match="SHA-256 mismatch"):
        verify_memory_fit_evidence(
            path,
            expected_sha256="f" * 64,
            expected_inventory_sha256="a" * 64,
            expected_tensor_bytes=1,
            expected_method_sha256="b" * 64,
            expected_evaluation_lock_sha256="d" * 64,
            expected_maximum_context_tokens=32768,
        )


def test_cold_path_requires_every_stage_and_margin_within_timeout(tmp_path: Path) -> None:
    evidence = {
        "schema_version": 1,
        "kind": "cold_path_time_evidence",
        "evaluation_lock_sha256": "d" * 64,
        "timeout_seconds": 2700,
        "transfer_seconds": 1200.5,
        "verification_seconds": 300,
        "load_seconds": 400,
        "evaluation_seconds": 600,
        "safety_margin_seconds": 200,
        "method_sha256": "c" * 64,
    }
    path = tmp_path / "time.json"
    digest = _write(path, evidence)
    result = verify_cold_path_time_evidence(
        path,
        expected_sha256=digest,
        timeout_seconds=2700,
        expected_method_sha256="c" * 64,
        expected_evaluation_lock_sha256="d" * 64,
    )
    assert result.proven is False
    assert result.required == 2700.5
    evidence["safety_margin_seconds"] = 199
    digest = _write(path, evidence)
    assert verify_cold_path_time_evidence(
        path,
        expected_sha256=digest,
        timeout_seconds=2700,
        expected_method_sha256="c" * 64,
        expected_evaluation_lock_sha256="d" * 64,
    ).proven


def test_cold_path_rejects_nan_and_timeout_drift(tmp_path: Path) -> None:
    evidence = {
        "schema_version": 1,
        "kind": "cold_path_time_evidence",
        "evaluation_lock_sha256": "d" * 64,
        "timeout_seconds": 2699,
        "transfer_seconds": float("nan"),
        "verification_seconds": 1,
        "load_seconds": 1,
        "evaluation_seconds": 1,
        "safety_margin_seconds": 1,
        "method_sha256": "c" * 64,
    }
    path = tmp_path / "time.json"
    digest = _write(path, evidence)
    with pytest.raises(ReferenceGateError, match="timeout mismatch"):
        verify_cold_path_time_evidence(
            path,
            expected_sha256=digest,
            timeout_seconds=2700,
            expected_method_sha256="c" * 64,
            expected_evaluation_lock_sha256="d" * 64,
        )


def test_provider_evidence_requires_exact_cap_billing_and_single_attempt(tmp_path: Path) -> None:
    evidence = {
        "schema_version": 1,
        "kind": "provider_safety_evidence",
        "provider": "modal",
        "workspace_scope_sha256": "a" * 64,
        "workspace_hard_cap_usd": "4.00",
        "billing_scope_sha256": "b" * 64,
        "billing_completeness_delay_seconds": 3600,
        "maximum_billable_attempts": 1,
        "observed_at": "2026-08-22T00:00:00+00:00",
        "method_sha256": "c" * 64,
    }
    path = tmp_path / "provider.json"
    digest = _write(path, evidence)
    assert verify_provider_safety_evidence(path, expected_sha256=digest)["proven"] is True
    evidence["maximum_billable_attempts"] = 2
    digest = _write(path, evidence)
    with pytest.raises(ReferenceGateError, match="one billable attempt"):
        verify_provider_safety_evidence(path, expected_sha256=digest)
