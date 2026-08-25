from __future__ import annotations

import hashlib
import json

from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE

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
APPROVED_TRUST_OVERRIDE_PLAN_SHA256 = (
    "277e2359b33f334e96aa60a4e146bb57a640c21b5e24d63d34d9f811c06b048e"
)
APPROVED_TRUST_OVERRIDE_PLAN_PATH = (
    "docs/plans/local/2026-08-23-provider-observation-trust-override-plan.md"
)
APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256 = (
    "4c34af650985ed9846d6fdfbba0547fa257c41d079cb0cc15c79d1bebe56effb"
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
    formula_approval_sha256: str,
    trust_override_sha256: str | None = None,
) -> str:
    """Bind the immutable inputs that define the one-attempt reference scope."""
    if IMMUTABLE_REVISION_RE.fullmatch(source_revision) is None:
        raise ValueError("source revision must be a lowercase immutable revision")
    for label, value in (
        ("weight inventory", weight_inventory_sha256),
        ("evaluation lock", evaluation_lock_sha256),
        ("formula authority", formula_authority_sha256),
        ("formula approval", formula_approval_sha256),
    ):
        if SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"{label} must be lowercase SHA-256")
    if trust_override_sha256 is not None and SHA256_RE.fullmatch(trust_override_sha256) is None:
        raise ValueError("trust override must be lowercase SHA-256")
    material = {
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
        "evaluation_lock_sha256": evaluation_lock_sha256,
        "formula_authority_sha256": formula_authority_sha256,
        "formula_approval_sha256": formula_approval_sha256,
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "resources": REFERENCE_RESOURCES,
        "source_revision": source_revision,
        "trust_override_sha256": trust_override_sha256,
        "weight_inventory_sha256": weight_inventory_sha256,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
