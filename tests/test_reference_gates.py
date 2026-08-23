from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lowbit_lab.reference_gates import (
    A100_80GB_BYTES,
    MEMORY_FORMULA,
    TIME_FORMULA,
    ReferenceGateError,
    verify_cold_path_time_evidence,
    verify_formula_authority,
    verify_memory_fit_evidence,
    verify_provider_billing_authority,
    verify_provider_constraint_contract,
    verify_provider_observation_receipt,
    verify_provider_safety_evidence,
)


def _write(path: Path, value: object) -> str:
    content = (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _provider_constraint_contract() -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "provider_constraint_contract",
        "provider": "modal",
        "workspace_scope_sha256": "a" * 64,
        "environment_scope_sha256": "b" * 64,
        "maximum_concurrent_containers": 1,
        "maximum_concurrent_gpus": 1,
        "provider_hard_budget_available": False,
        "provider_crash_rescheduling_bounded": False,
        "observation_method_sha256": "c" * 64,
        "approved_amendment_sha256": "d" * 64,
    }


def _provider_observation_receipt(
    contract_sha256: str, *, observed_at: datetime
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "provider_constraint_observation_receipt",
        "provider": "modal",
        "workspace_scope_sha256": "a" * 64,
        "environment_scope_sha256": "b" * 64,
        "approved_amendment_sha256": "d" * 64,
        "constraint_contract_sha256": contract_sha256,
        "screenshot_sha256": "e" * 64,
        "observed_maximum_concurrent_containers": 1,
        "observed_maximum_concurrent_gpus": 1,
        "active_containers": 0,
        "active_gpus": 0,
        "observed_at": observed_at.isoformat(),
    }


def _provider_billing_authority() -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "provider_billing_authority_contract",
        "provider": "modal",
        "environment_scope_sha256": "b" * 64,
        "attribution_method_sha256": "f" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_completeness_delay_seconds": 3600,
    }


def test_formula_authority_is_closed_exact_and_reviewable(tmp_path: Path) -> None:
    authority = {
        "schema_version": 1,
        "kind": "reference_formula_authority",
        "authority_id": "reference-resource-accounting",
        "authority_version": "1.0.0",
        "memory_formula": MEMORY_FORMULA,
        "time_formula": TIME_FORMULA,
        "maximum_gpu_memory_bytes": A100_80GB_BYTES,
        "maximum_context_tokens": 262144,
        "timeout_seconds": 2700,
        "approval_status": "pending_human_review",
    }
    path = tmp_path / "formula.json"
    digest = _write(path, authority)
    result = verify_formula_authority(
        path,
        expected_sha256=digest,
        expected_maximum_context_tokens=262144,
        expected_timeout_seconds=2700,
    )
    assert result["verified"] is True
    assert result["human_approved"] is False
    authority["approval_status"] = "self_asserted"
    digest = _write(path, authority)
    with pytest.raises(ReferenceGateError, match="approval status"):
        verify_formula_authority(
            path,
            expected_sha256=digest,
            expected_maximum_context_tokens=262144,
            expected_timeout_seconds=2700,
        )


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


def test_provider_constraint_contract_accepts_only_the_approved_residual_risk(
    tmp_path: Path,
) -> None:
    contract = _provider_constraint_contract()
    path = tmp_path / "constraint.json"
    digest = _write(path, contract)

    result = verify_provider_constraint_contract(
        path,
        expected_sha256=digest,
        expected_workspace_scope_sha256="a" * 64,
        expected_environment_scope_sha256="b" * 64,
        expected_amendment_sha256="d" * 64,
    )

    assert result == {
        "proven": True,
        "evidence_sha256": digest,
        "workspace_scope_sha256": "a" * 64,
        "environment_scope_sha256": "b" * 64,
        "observation_method_sha256": "c" * 64,
        "approved_amendment_sha256": "d" * 64,
        "maximum_concurrent_containers": 1,
        "maximum_concurrent_gpus": 1,
        "provider_hard_budget_available": False,
        "provider_crash_rescheduling_bounded": False,
    }

    for field, value, message in (
        ("provider_hard_budget_available", True, "hard budget"),
        ("provider_crash_rescheduling_bounded", True, "crash rescheduling"),
        ("maximum_concurrent_containers", 2, "container"),
        ("maximum_concurrent_gpus", 2, "GPU"),
    ):
        changed = dict(contract)
        changed[field] = value
        changed_digest = _write(path, changed)
        with pytest.raises(ReferenceGateError, match=message):
            verify_provider_constraint_contract(
                path,
                expected_sha256=changed_digest,
                expected_workspace_scope_sha256="a" * 64,
                expected_environment_scope_sha256="b" * 64,
                expected_amendment_sha256="d" * 64,
            )


def test_provider_constraint_contract_rejects_scope_digest_and_amendment_drift(
    tmp_path: Path,
) -> None:
    contract = _provider_constraint_contract()
    path = tmp_path / "constraint.json"
    digest = _write(path, contract)

    for argument, value, message in (
        ("expected_workspace_scope_sha256", "9" * 64, "workspace scope"),
        ("expected_environment_scope_sha256", "8" * 64, "environment scope"),
        ("expected_amendment_sha256", "7" * 64, "amendment"),
    ):
        expected = {
            "expected_workspace_scope_sha256": "a" * 64,
            "expected_environment_scope_sha256": "b" * 64,
            "expected_amendment_sha256": "d" * 64,
        }
        expected[argument] = value
        with pytest.raises(ReferenceGateError, match=message):
            verify_provider_constraint_contract(path, expected_sha256=digest, **expected)

    contract["unknown"] = "not allowed"
    digest = _write(path, contract)
    with pytest.raises(ReferenceGateError, match="closed"):
        verify_provider_constraint_contract(
            path,
            expected_sha256=digest,
            expected_workspace_scope_sha256="a" * 64,
            expected_environment_scope_sha256="b" * 64,
            expected_amendment_sha256="d" * 64,
        )

    contract.pop("unknown")
    contract["schema_version"] = 1
    digest = _write(path, contract)
    with pytest.raises(ReferenceGateError, match="unsupported"):
        verify_provider_constraint_contract(
            path,
            expected_sha256=digest,
            expected_workspace_scope_sha256="a" * 64,
            expected_environment_scope_sha256="b" * 64,
            expected_amendment_sha256="d" * 64,
        )


def test_provider_observation_receipt_accepts_exact_fresh_boundaries(tmp_path: Path) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    path = tmp_path / "receipt.json"

    for maximum_age_seconds in (15 * 60, 30 * 60):
        receipt = _provider_observation_receipt(
            "2" * 64,
            observed_at=validated_at - timedelta(seconds=maximum_age_seconds),
        )
        digest = _write(path, receipt)
        result = verify_provider_observation_receipt(
            path,
            expected_sha256=digest,
            expected_contract_sha256="2" * 64,
            expected_workspace_scope_sha256="a" * 64,
            expected_environment_scope_sha256="b" * 64,
            expected_amendment_sha256="d" * 64,
            validated_at=validated_at,
            maximum_age_seconds=maximum_age_seconds,
        )
        assert result["proven"] is True
        assert result["age_seconds"] == maximum_age_seconds
        assert "provider" not in result
        assert "screenshot" not in result


@pytest.mark.parametrize("maximum_age_seconds", [15 * 60, 30 * 60])
def test_provider_observation_receipt_rejects_stale_at_each_gate(
    tmp_path: Path, maximum_age_seconds: int
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    receipt = _provider_observation_receipt(
        "2" * 64,
        observed_at=validated_at - timedelta(seconds=maximum_age_seconds + 1),
    )
    path = tmp_path / "receipt.json"
    digest = _write(path, receipt)
    with pytest.raises(ReferenceGateError, match="stale"):
        verify_provider_observation_receipt(
            path,
            expected_sha256=digest,
            expected_contract_sha256="2" * 64,
            expected_workspace_scope_sha256="a" * 64,
            expected_environment_scope_sha256="b" * 64,
            expected_amendment_sha256="d" * 64,
            validated_at=validated_at,
            maximum_age_seconds=maximum_age_seconds,
        )


def test_provider_observation_receipt_rejects_active_resources_and_limit_drift(
    tmp_path: Path,
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    receipt = _provider_observation_receipt("2" * 64, observed_at=validated_at)
    path = tmp_path / "receipt.json"

    for field, value, message in (
        ("active_containers", 1, "active resources"),
        ("active_gpus", 1, "active resources"),
        ("observed_maximum_concurrent_containers", 2, "container"),
        ("observed_maximum_concurrent_gpus", 2, "GPU"),
    ):
        changed = dict(receipt)
        changed[field] = value
        digest = _write(path, changed)
        with pytest.raises(ReferenceGateError, match=message):
            verify_provider_observation_receipt(
                path,
                expected_sha256=digest,
                expected_contract_sha256="2" * 64,
                expected_workspace_scope_sha256="a" * 64,
                expected_environment_scope_sha256="b" * 64,
                expected_amendment_sha256="d" * 64,
                validated_at=validated_at,
                maximum_age_seconds=900,
            )


def test_provider_observation_receipt_rejects_identity_and_binding_mismatch(
    tmp_path: Path,
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    receipt = _provider_observation_receipt("2" * 64, observed_at=validated_at)
    path = tmp_path / "receipt.json"
    digest = _write(path, receipt)

    for argument, value, message in (
        ("expected_contract_sha256", "3" * 64, "contract"),
        ("expected_workspace_scope_sha256", "4" * 64, "workspace scope"),
        ("expected_environment_scope_sha256", "5" * 64, "environment scope"),
        ("expected_amendment_sha256", "6" * 64, "amendment"),
    ):
        expected: dict[str, object] = {
            "expected_contract_sha256": "2" * 64,
            "expected_workspace_scope_sha256": "a" * 64,
            "expected_environment_scope_sha256": "b" * 64,
            "expected_amendment_sha256": "d" * 64,
            "validated_at": validated_at,
            "maximum_age_seconds": 900,
        }
        expected[argument] = value
        with pytest.raises(ReferenceGateError, match=message):
            verify_provider_observation_receipt(path, expected_sha256=digest, **expected)

    receipt["observed_at"] = "2026-08-22T12:00:00"
    digest = _write(path, receipt)
    with pytest.raises(ReferenceGateError, match="timezone-aware"):
        verify_provider_observation_receipt(
            path,
            expected_sha256=digest,
            expected_contract_sha256="2" * 64,
            expected_workspace_scope_sha256="a" * 64,
            expected_environment_scope_sha256="b" * 64,
            expected_amendment_sha256="d" * 64,
            validated_at=validated_at,
            maximum_age_seconds=900,
        )


def test_provider_billing_authority_binds_scope_and_required_semantics(tmp_path: Path) -> None:
    authority = _provider_billing_authority()
    path = tmp_path / "billing.json"
    digest = _write(path, authority)
    result = verify_provider_billing_authority(
        path,
        expected_sha256=digest,
        expected_environment_scope_sha256="b" * 64,
    )
    assert result == {
        "proven": True,
        "evidence_sha256": digest,
        "environment_scope_sha256": "b" * 64,
        "attribution_method_sha256": "f" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_completeness_delay_seconds": 3600,
    }

    for field, value, message in (
        ("attribution_method_sha256", None, "attribution_method_sha256"),
        ("authoritative_report_identity_sha256", None, "authoritative_report_identity_sha256"),
        ("billing_completeness_delay_seconds", 0, "positive integer"),
    ):
        changed = dict(authority)
        changed[field] = value
        changed_digest = _write(path, changed)
        with pytest.raises(ReferenceGateError, match=message):
            verify_provider_billing_authority(
                path,
                expected_sha256=changed_digest,
                expected_environment_scope_sha256="b" * 64,
            )

    digest = _write(path, authority)
    with pytest.raises(ReferenceGateError, match="environment scope"):
        verify_provider_billing_authority(
            path,
            expected_sha256=digest,
            expected_environment_scope_sha256="9" * 64,
        )
