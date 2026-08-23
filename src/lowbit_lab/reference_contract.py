from __future__ import annotations

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
