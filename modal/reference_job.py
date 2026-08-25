"""Declarative Modal reference specification; deliberately has no submit entrypoint."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from lowbit_lab.reference_contract import REFERENCE_RESOURCES

REFERENCE_FUNCTION_SPEC: dict[str, Any] = {
    "gpu": REFERENCE_RESOURCES["gpu_type"],
    "gpu_count": REFERENCE_RESOURCES["gpu_count"],
    "cpu_cores": REFERENCE_RESOURCES["cpu_cores"],
    "memory_mib": int(REFERENCE_RESOURCES["memory_gib"]) * 1024,
    "ephemeral_disk_mib": int(REFERENCE_RESOURCES["ephemeral_disk_gib"]) * 1024,
    "timeout_seconds": REFERENCE_RESOURCES["timeout_seconds"],
    "startup_timeout_seconds": REFERENCE_RESOURCES["startup_timeout_seconds"],
    "retries": REFERENCE_RESOURCES["retries"],
    "schedule": None,
    "mounts": [],
    "volumes": [],
    "secrets": [],
    "cloud_upload": False,
    "submission_supported": False,
}


def reference_function_spec() -> dict[str, Any]:
    """Return an isolated copy so callers cannot mutate the reviewed declaration."""

    return deepcopy(REFERENCE_FUNCTION_SPEC)
