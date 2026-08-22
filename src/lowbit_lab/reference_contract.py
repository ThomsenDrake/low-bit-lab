from __future__ import annotations

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
