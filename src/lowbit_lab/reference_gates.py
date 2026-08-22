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
    if available > 80 * 1024**3:
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
