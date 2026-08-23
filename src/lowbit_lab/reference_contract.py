from __future__ import annotations

import hashlib
import json
import re

ORIGINAL_APPROVED_PLAN_SHA256 = (
    "a45e791c83466f545f6ac204857722478a080a1ea4a007c47510fbc4aa2b86c4"
)
ORIGINAL_APPROVED_PLAN_PATH = (
    "docs/plans/local/2026-08-21-2358-feat-full-weight-baseline-plan.md"
)
APPROVED_PROVIDER_AMENDMENT_SHA256 = (
    "0de9ff2c7ae791d524e59e6018b0356ea0d95ec9782754eaef411db8862ee114"
)
APPROVED_PROVIDER_AMENDMENT_PATH = (
    "docs/plans/local/2026-08-22-1126-feat-provider-constraint-amendment-plan.md"
)
PROVIDER_APPROVAL_OBSERVATION_MAX_AGE_SECONDS = 15 * 60

REFERENCE_RESOURCES: dict[str, object] = {
    "gpu_type": "A100-80GB",
    "gpu_count": 1,
    "cpu_cores": 8,
    "memory_gib": 96,
    "ephemeral_disk_gib": 90,
    "timeout_seconds": 2700,
    "startup_timeout_seconds": None,
    "retries": 0,
}


def reference_execution_scope_sha256(
    *,
    source_revision: str,
    weight_inventory_sha256: str,
    evaluation_lock_sha256: str,
    formula_authority_sha256: str,
) -> str:
    """Bind the immutable inputs that define the one-attempt reference scope."""
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise ValueError("source revision must be a lowercase immutable 40-character revision")
    for label, value in (
        ("weight inventory", weight_inventory_sha256),
        ("evaluation lock", evaluation_lock_sha256),
        ("formula authority", formula_authority_sha256),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"{label} must be lowercase SHA-256")
    material = {
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "evaluation_lock_sha256": evaluation_lock_sha256,
        "formula_authority_sha256": formula_authority_sha256,
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "resources": REFERENCE_RESOURCES,
        "source_revision": source_revision,
        "weight_inventory_sha256": weight_inventory_sha256,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
