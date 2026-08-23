from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE


class ReferenceGateError(ValueError):
    pass


MEMORY_FORMULA = (
    "tensor_bytes+runtime_overhead_bytes+kv_cache_bytes+allocator_reserve_bytes"
    "<=usable_gpu_memory_bytes"
)
TIME_FORMULA = (
    "transfer_seconds+verification_seconds+load_seconds+evaluation_seconds"
    "+safety_margin_seconds<=timeout_seconds"
)
A100_80GB_BYTES = 80 * 1024**3


@dataclass(frozen=True)
class GateResult:
    proven: bool
    evidence_sha256: str
    required: int | float
    available: int | float


def _closed(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ReferenceGateError(f"{label} schema is closed")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReferenceGateError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReferenceGateError(f"{label} must be a non-negative integer")
    return value


def _nonnegative_number(value: object, label: str) -> float:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ReferenceGateError(f"{label} must be a finite non-negative number")
    return float(value)


def _positive_number(value: object, label: str) -> float:
    parsed = _nonnegative_number(value, label)
    if parsed == 0:
        raise ReferenceGateError(f"{label} must be positive")
    return parsed


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReferenceGateError(f"{label} must be a lowercase SHA-256")
    return value


def _load(path: Path, expected_sha256: str) -> tuple[Mapping[str, Any], str]:
    try:
        content = path.read_bytes()
        raw = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceGateError("cannot read gate evidence") from exc
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected_sha256:
        raise ReferenceGateError("gate evidence SHA-256 mismatch")
    if not isinstance(raw, Mapping):
        raise ReferenceGateError("gate evidence must be an object")
    return raw, actual


def verify_formula_authority(
    path: Path,
    *,
    expected_sha256: str,
    expected_maximum_context_tokens: int,
    expected_timeout_seconds: int,
) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    authority = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "authority_id",
            "authority_version",
            "memory_formula",
            "time_formula",
            "maximum_gpu_memory_bytes",
            "maximum_context_tokens",
            "timeout_seconds",
            "approval_status",
        },
        "formula authority",
    )
    if authority["schema_version"] != 1 or authority["kind"] != "reference_formula_authority":
        raise ReferenceGateError("unsupported formula authority")
    if (
        authority["authority_id"] != "reference-resource-accounting"
        or authority["authority_version"] != "1.0.0"
        or authority["memory_formula"] != MEMORY_FORMULA
        or authority["time_formula"] != TIME_FORMULA
    ):
        raise ReferenceGateError("formula authority method is unsupported")
    if (
        _positive_int(authority["maximum_gpu_memory_bytes"], "maximum_gpu_memory_bytes")
        != A100_80GB_BYTES
        or _positive_int(authority["maximum_context_tokens"], "maximum_context_tokens")
        != expected_maximum_context_tokens
        or _positive_int(authority["timeout_seconds"], "timeout_seconds")
        != expected_timeout_seconds
    ):
        raise ReferenceGateError("formula authority envelope mismatch")
    if authority["approval_status"] not in {"pending_human_review", "approved"}:
        raise ReferenceGateError("formula authority approval status is unknown")
    return {
        "verified": True,
        "human_approved": authority["approval_status"] == "approved",
        "evidence_sha256": digest,
    }


def verify_memory_fit_evidence(
    path: Path,
    *,
    expected_sha256: str,
    expected_inventory_sha256: str,
    expected_tensor_bytes: int,
    expected_method_sha256: str,
    expected_evaluation_lock_sha256: str,
    expected_maximum_context_tokens: int,
) -> GateResult:
    raw, digest = _load(path, expected_sha256)
    evidence = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "inventory_sha256",
            "evaluation_lock_sha256",
            "maximum_context_tokens",
            "tensor_bytes",
            "runtime_overhead_bytes",
            "kv_cache_bytes",
            "allocator_reserve_bytes",
            "usable_gpu_memory_bytes",
            "method_sha256",
        },
        "memory-fit evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != "memory_fit_evidence":
        raise ReferenceGateError("unsupported memory-fit evidence")
    if _sha256(evidence["inventory_sha256"], "inventory_sha256") != expected_inventory_sha256:
        raise ReferenceGateError("memory-fit inventory mismatch")
    if (
        _sha256(evidence["evaluation_lock_sha256"], "evaluation_lock_sha256")
        != expected_evaluation_lock_sha256
        or _positive_int(evidence["maximum_context_tokens"], "maximum_context_tokens")
        != expected_maximum_context_tokens
    ):
        raise ReferenceGateError("memory-fit evaluation context mismatch")
    if _positive_int(evidence["tensor_bytes"], "tensor_bytes") != expected_tensor_bytes:
        raise ReferenceGateError("memory-fit tensor byte count mismatch")
    required = sum(
        _positive_int(evidence[name], name)
        for name in (
            "tensor_bytes",
            "runtime_overhead_bytes",
            "kv_cache_bytes",
            "allocator_reserve_bytes",
        )
    )
    available = _positive_int(evidence["usable_gpu_memory_bytes"], "usable_gpu_memory_bytes")
    if _sha256(evidence["method_sha256"], "method_sha256") != expected_method_sha256:
        raise ReferenceGateError("memory-fit method authority mismatch")
    if available > A100_80GB_BYTES:
        raise ReferenceGateError("usable GPU memory exceeds the A100-80GB hard envelope")
    return GateResult(required <= available, digest, required, available)


def verify_cold_path_time_evidence(
    path: Path,
    *,
    expected_sha256: str,
    timeout_seconds: int,
    expected_method_sha256: str,
    expected_evaluation_lock_sha256: str,
) -> GateResult:
    raw, digest = _load(path, expected_sha256)
    evidence = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "evaluation_lock_sha256",
            "timeout_seconds",
            "transfer_seconds",
            "verification_seconds",
            "load_seconds",
            "evaluation_seconds",
            "safety_margin_seconds",
            "method_sha256",
        },
        "cold-path time evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != "cold_path_time_evidence":
        raise ReferenceGateError("unsupported cold-path time evidence")
    if (
        _sha256(evidence["evaluation_lock_sha256"], "evaluation_lock_sha256")
        != expected_evaluation_lock_sha256
    ):
        raise ReferenceGateError("cold-path evaluation lock mismatch")
    if _positive_int(evidence["timeout_seconds"], "timeout_seconds") != timeout_seconds:
        raise ReferenceGateError("cold-path timeout mismatch")
    required = sum(
        _positive_number(evidence[name], name)
        for name in (
            "transfer_seconds",
            "verification_seconds",
            "load_seconds",
            "evaluation_seconds",
            "safety_margin_seconds",
        )
    )
    if _sha256(evidence["method_sha256"], "method_sha256") != expected_method_sha256:
        raise ReferenceGateError("cold-path method authority mismatch")
    return GateResult(required <= timeout_seconds, digest, required, timeout_seconds)


def verify_provider_constraint_contract(
    path: Path,
    *,
    expected_sha256: str,
    expected_workspace_scope_sha256: str,
    expected_environment_scope_sha256: str,
    expected_amendment_sha256: str,
) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    contract = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "provider",
            "workspace_scope_sha256",
            "environment_scope_sha256",
            "maximum_concurrent_containers",
            "maximum_concurrent_gpus",
            "provider_hard_budget_available",
            "provider_crash_rescheduling_bounded",
            "observation_method_sha256",
            "approved_amendment_sha256",
        },
        "provider constraint contract",
    )
    if contract["schema_version"] != 2 or contract["kind"] != "provider_constraint_contract":
        raise ReferenceGateError("unsupported provider constraint contract")
    if contract["provider"] != "modal":
        raise ReferenceGateError("provider identity mismatch")

    workspace_scope = _sha256(contract["workspace_scope_sha256"], "workspace_scope_sha256")
    environment_scope = _sha256(
        contract["environment_scope_sha256"], "environment_scope_sha256"
    )
    method_sha256 = _sha256(contract["observation_method_sha256"], "observation_method_sha256")
    amendment_sha256 = _sha256(
        contract["approved_amendment_sha256"], "approved_amendment_sha256"
    )
    if workspace_scope != expected_workspace_scope_sha256:
        raise ReferenceGateError("provider workspace scope mismatch")
    if environment_scope != expected_environment_scope_sha256:
        raise ReferenceGateError("provider environment scope mismatch")
    if amendment_sha256 != expected_amendment_sha256:
        raise ReferenceGateError("provider amendment binding mismatch")

    maximum_containers = _positive_int(
        contract["maximum_concurrent_containers"], "maximum_concurrent_containers"
    )
    maximum_gpus = _positive_int(
        contract["maximum_concurrent_gpus"], "maximum_concurrent_gpus"
    )
    if maximum_containers != 1:
        raise ReferenceGateError("provider container concurrency limit must equal one")
    if maximum_gpus != 1:
        raise ReferenceGateError("provider GPU concurrency limit must equal one")
    if contract["provider_hard_budget_available"] is not False:
        raise ReferenceGateError("provider hard budget must be explicitly unavailable")
    if contract["provider_crash_rescheduling_bounded"] is not False:
        raise ReferenceGateError("provider crash rescheduling must be explicitly unbounded")

    return {
        "proven": True,
        "evidence_sha256": digest,
        "workspace_scope_sha256": workspace_scope,
        "environment_scope_sha256": environment_scope,
        "observation_method_sha256": method_sha256,
        "approved_amendment_sha256": amendment_sha256,
        "maximum_concurrent_containers": maximum_containers,
        "maximum_concurrent_gpus": maximum_gpus,
        "provider_hard_budget_available": False,
        "provider_crash_rescheduling_bounded": False,
    }


def _verify_provider_observation_receipt(
    path: Path,
    *,
    expected_sha256: str,
    expected_contract_sha256: str,
    expected_workspace_scope_sha256: str,
    expected_environment_scope_sha256: str,
    expected_amendment_sha256: str,
    validated_at: datetime,
    maximum_age_seconds: int | None,
) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    receipt = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "provider",
            "workspace_scope_sha256",
            "environment_scope_sha256",
            "approved_amendment_sha256",
            "constraint_contract_sha256",
            "screenshot_sha256",
            "observed_maximum_concurrent_containers",
            "observed_maximum_concurrent_gpus",
            "active_containers",
            "active_gpus",
            "observed_at",
        },
        "provider observation receipt",
    )
    if (
        receipt["schema_version"] != 2
        or receipt["kind"] != "provider_constraint_observation_receipt"
    ):
        raise ReferenceGateError("unsupported provider observation receipt")
    if receipt["provider"] != "modal":
        raise ReferenceGateError("provider identity mismatch")

    workspace_scope = _sha256(receipt["workspace_scope_sha256"], "workspace_scope_sha256")
    environment_scope = _sha256(
        receipt["environment_scope_sha256"], "environment_scope_sha256"
    )
    amendment_sha256 = _sha256(
        receipt["approved_amendment_sha256"], "approved_amendment_sha256"
    )
    contract_sha256 = _sha256(
        receipt["constraint_contract_sha256"], "constraint_contract_sha256"
    )
    screenshot_sha256 = _sha256(receipt["screenshot_sha256"], "screenshot_sha256")
    if workspace_scope != expected_workspace_scope_sha256:
        raise ReferenceGateError("provider workspace scope mismatch")
    if environment_scope != expected_environment_scope_sha256:
        raise ReferenceGateError("provider environment scope mismatch")
    if amendment_sha256 != expected_amendment_sha256:
        raise ReferenceGateError("provider amendment binding mismatch")
    if contract_sha256 != expected_contract_sha256:
        raise ReferenceGateError("provider constraint contract mismatch")

    maximum_containers = _positive_int(
        receipt["observed_maximum_concurrent_containers"],
        "observed_maximum_concurrent_containers",
    )
    maximum_gpus = _positive_int(
        receipt["observed_maximum_concurrent_gpus"], "observed_maximum_concurrent_gpus"
    )
    if maximum_containers != 1:
        raise ReferenceGateError("observed provider container limit must equal one")
    if maximum_gpus != 1:
        raise ReferenceGateError("observed provider GPU limit must equal one")
    active_containers = _nonnegative_int(receipt["active_containers"], "active_containers")
    active_gpus = _nonnegative_int(receipt["active_gpus"], "active_gpus")
    if active_containers != 0 or active_gpus != 0:
        raise ReferenceGateError("provider observation contains active resources")

    if not isinstance(receipt["observed_at"], str):
        raise ReferenceGateError("provider observation time is invalid")
    try:
        observed_at = datetime.fromisoformat(receipt["observed_at"])
    except ValueError as exc:
        raise ReferenceGateError("provider observation time is invalid") from exc
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ReferenceGateError("provider observation time must be timezone-aware")
    if validated_at.tzinfo is None or validated_at.utcoffset() is None:
        raise ReferenceGateError("validation time must be timezone-aware")
    age_seconds = (validated_at - observed_at).total_seconds()
    if age_seconds < 0:
        raise ReferenceGateError("provider observation time is in the future")
    if maximum_age_seconds is not None and age_seconds > _positive_int(
        maximum_age_seconds, "maximum_age_seconds"
    ):
        raise ReferenceGateError("provider observation receipt is stale")

    return {
        "proven": True,
        "evidence_sha256": digest,
        "workspace_scope_sha256": workspace_scope,
        "environment_scope_sha256": environment_scope,
        "approved_amendment_sha256": amendment_sha256,
        "constraint_contract_sha256": contract_sha256,
        "screenshot_sha256": screenshot_sha256,
        "maximum_concurrent_containers": maximum_containers,
        "maximum_concurrent_gpus": maximum_gpus,
        "active_containers": active_containers,
        "active_gpus": active_gpus,
        "observed_at": observed_at.isoformat(),
        "age_seconds": age_seconds,
        "fresh": maximum_age_seconds is not None,
    }


def verify_provider_observation_receipt(
    path: Path,
    *,
    expected_sha256: str,
    expected_contract_sha256: str,
    expected_workspace_scope_sha256: str,
    expected_environment_scope_sha256: str,
    expected_amendment_sha256: str,
    validated_at: datetime,
    maximum_age_seconds: int,
) -> dict[str, object]:
    return _verify_provider_observation_receipt(
        path,
        expected_sha256=expected_sha256,
        expected_contract_sha256=expected_contract_sha256,
        expected_workspace_scope_sha256=expected_workspace_scope_sha256,
        expected_environment_scope_sha256=expected_environment_scope_sha256,
        expected_amendment_sha256=expected_amendment_sha256,
        validated_at=validated_at,
        maximum_age_seconds=maximum_age_seconds,
    )


def verify_provider_observation_receipt_for_trust_override(
    path: Path,
    *,
    expected_sha256: str,
    expected_contract_sha256: str,
    expected_workspace_scope_sha256: str,
    expected_environment_scope_sha256: str,
    expected_amendment_sha256: str,
    validated_at: datetime,
) -> dict[str, object]:
    """Verify every observation claim except freshness for a separately approved override."""
    return _verify_provider_observation_receipt(
        path,
        expected_sha256=expected_sha256,
        expected_contract_sha256=expected_contract_sha256,
        expected_workspace_scope_sha256=expected_workspace_scope_sha256,
        expected_environment_scope_sha256=expected_environment_scope_sha256,
        expected_amendment_sha256=expected_amendment_sha256,
        validated_at=validated_at,
        maximum_age_seconds=None,
    )


def verify_provider_billing_authority(
    path: Path,
    *,
    expected_sha256: str,
    expected_environment_scope_sha256: str,
) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    authority = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "provider",
            "environment_scope_sha256",
            "attribution_method_sha256",
            "authoritative_report_identity_sha256",
            "billing_completeness_delay_seconds",
        },
        "provider billing authority contract",
    )
    if (
        authority["schema_version"] != 2
        or authority["kind"] != "provider_billing_authority_contract"
    ):
        raise ReferenceGateError("unsupported provider billing authority contract")
    if authority["provider"] != "modal":
        raise ReferenceGateError("provider identity mismatch")
    environment_scope = _sha256(
        authority["environment_scope_sha256"], "environment_scope_sha256"
    )
    if environment_scope != expected_environment_scope_sha256:
        raise ReferenceGateError("provider billing environment scope mismatch")
    attribution_method = _sha256(
        authority["attribution_method_sha256"], "attribution_method_sha256"
    )
    report_identity = _sha256(
        authority["authoritative_report_identity_sha256"],
        "authoritative_report_identity_sha256",
    )
    completeness_delay = _positive_int(
        authority["billing_completeness_delay_seconds"],
        "billing_completeness_delay_seconds",
    )
    return {
        "proven": True,
        "evidence_sha256": digest,
        "environment_scope_sha256": environment_scope,
        "attribution_method_sha256": attribution_method,
        "authoritative_report_identity_sha256": report_identity,
        "billing_completeness_delay_seconds": completeness_delay,
    }


def verify_provider_observation_trust_override(
    path: Path,
    *,
    expected_sha256: str,
    expected_original_plan_sha256: str,
    expected_provider_amendment_sha256: str,
    expected_trust_override_plan_sha256: str,
    expected_contract_sha256: str,
    expected_observation_receipt_sha256: str,
    expected_screenshot_sha256: str,
    expected_workspace_scope_sha256: str,
    expected_environment_scope_sha256: str,
    expected_human_statement_sha256: str,
) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    override = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "original_approved_plan_sha256",
            "approved_provider_amendment_sha256",
            "approved_trust_override_plan_sha256",
            "constraint_contract_sha256",
            "observation_receipt_sha256",
            "screenshot_sha256",
            "workspace_scope_sha256",
            "environment_scope_sha256",
            "human_approval_statement_sha256",
            "human_approved",
            "observation_is_stale",
            "configuration_drift_risk_accepted",
            "provider_residual_cost_risk_accepted",
            "provider_hard_budget_available",
        },
        "provider observation trust override",
    )
    if (
        override["schema_version"] != 1
        or override["kind"] != "provider_observation_trust_override"
    ):
        raise ReferenceGateError("unsupported provider observation trust override")
    expected = {
        "original_approved_plan_sha256": expected_original_plan_sha256,
        "approved_provider_amendment_sha256": expected_provider_amendment_sha256,
        "approved_trust_override_plan_sha256": expected_trust_override_plan_sha256,
        "constraint_contract_sha256": expected_contract_sha256,
        "observation_receipt_sha256": expected_observation_receipt_sha256,
        "screenshot_sha256": expected_screenshot_sha256,
        "workspace_scope_sha256": expected_workspace_scope_sha256,
        "environment_scope_sha256": expected_environment_scope_sha256,
        "human_approval_statement_sha256": expected_human_statement_sha256,
    }
    for field, expected_value in expected.items():
        if _sha256(override[field], field) != expected_value:
            raise ReferenceGateError(f"provider trust override {field} mismatch")
    required_true = (
        "human_approved",
        "observation_is_stale",
        "configuration_drift_risk_accepted",
        "provider_residual_cost_risk_accepted",
    )
    if any(override[field] is not True for field in required_true):
        raise ReferenceGateError("provider trust override risk acceptance is incomplete")
    if override["provider_hard_budget_available"] is not False:
        raise ReferenceGateError("provider trust override cannot claim a hard budget")
    return {
        "proven": True,
        "evidence_sha256": digest,
        "authority_mode": "human_trust_override",
        "observation_is_stale": True,
        "configuration_drift_risk_accepted": True,
        "provider_residual_cost_risk_accepted": True,
    }


def verify_provider_safety_evidence(path: Path, *, expected_sha256: str) -> dict[str, object]:
    raw, digest = _load(path, expected_sha256)
    evidence = _closed(
        raw,
        {
            "schema_version",
            "kind",
            "provider",
            "workspace_scope_sha256",
            "workspace_hard_cap_usd",
            "billing_scope_sha256",
            "billing_completeness_delay_seconds",
            "maximum_billable_attempts",
            "observed_at",
            "method_sha256",
        },
        "provider safety evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != "provider_safety_evidence":
        raise ReferenceGateError("unsupported provider safety evidence")
    if evidence["provider"] != "modal" or evidence["workspace_hard_cap_usd"] != "4.00":
        raise ReferenceGateError("provider identity or hard cap mismatch")
    for name in ("workspace_scope_sha256", "billing_scope_sha256", "method_sha256"):
        _sha256(evidence[name], name)
    _positive_int(
        evidence["billing_completeness_delay_seconds"],
        "billing_completeness_delay_seconds",
    )
    if evidence["maximum_billable_attempts"] != 1:
        raise ReferenceGateError("provider rescheduling is not bounded to one billable attempt")
    try:
        observed_at = datetime.fromisoformat(str(evidence["observed_at"]))
    except ValueError as exc:
        raise ReferenceGateError("provider observation time is invalid") from exc
    if observed_at.tzinfo is None:
        raise ReferenceGateError("provider observation time must be timezone-aware")
    return {"proven": True, "evidence_sha256": digest}
