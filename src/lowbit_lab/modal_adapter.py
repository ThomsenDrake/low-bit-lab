"""The sole audited Modal submission primitive; unreachable without DB capability evidence."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from lowbit_lab.db import DatabaseError, ResultsDatabase
from lowbit_lab.handoff import canonical_json, sha256_json
from lowbit_lab.provider_smoke import (
    SMOKE_RESOURCE_SPEC,
    ProviderSmokeCapability,
    ProviderSmokeError,
)


def _claim_capability(capability: ProviderSmokeCapability) -> None:
    try:
        ResultsDatabase(capability.db_path).claim_provider_smoke_submission(
            reservation_id=capability.reservation_id,
            owner_id=capability.owner_id,
            action_contract_sha256=capability.action_contract_sha256,
            execution_scope_sha256=capability.execution_scope_sha256,
            provider_environment=capability.provider_environment,
            occurred_at=datetime.now(UTC).isoformat(),
        )
    except (DatabaseError, sqlite3.Error) as exc:
        raise ProviderSmokeError(f"cannot claim execution capability: {exc}") from exc


def submit_provider_smoke(capability: ProviderSmokeCapability) -> dict[str, Any]:
    """Submit the bounded no-input smoke only after durable authority evidence exists."""
    _claim_capability(capability)
    database = ResultsDatabase(capability.db_path)
    stage = "submission_claimed"
    try:
        import modal

        app = modal.App("low-bit-lab-provider-smoke", include_source=False)

        @app.function(
            gpu=SMOKE_RESOURCE_SPEC["gpu"],
            cpu=SMOKE_RESOURCE_SPEC["cpu_cores"],
            memory=SMOKE_RESOURCE_SPEC["memory_mib"],
            ephemeral_disk=SMOKE_RESOURCE_SPEC["ephemeral_disk_mib"],
            timeout=SMOKE_RESOURCE_SPEC["timeout_seconds"],
            retries=SMOKE_RESOURCE_SPEC["retries"],
            max_containers=SMOKE_RESOURCE_SPEC["max_containers"],
            secrets=SMOKE_RESOURCE_SPEC["secrets"],
            volumes=SMOKE_RESOURCE_SPEC["volumes"],
            block_network=True,
            restrict_modal_access=True,
            single_use_containers=True,
            serialized=SMOKE_RESOURCE_SPEC["serialized_function"],
        )
        def observe() -> dict[str, Any]:
            query = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,compute_cap",
                    "--format=csv,noheader",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return {
                "schema_version": 1,
                "python": (
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                "gpu_observation": query.stdout.strip()[:256],
                "nvidia_smi_exit_code": query.returncode,
            }

        with app.run(environment_name=capability.provider_environment):
            call = observe.spawn()
            provider_call_id = call.object_id
            database.mark_provider_smoke_submitted(
                capability.reservation_id,
                owner_id=capability.owner_id,
                provider_call_id=provider_call_id,
                occurred_at=datetime.now(UTC).isoformat(),
            )
            stage = "submitted"
            observation = call.get(timeout=SMOKE_RESOURCE_SPEC["timeout_seconds"])
            if not isinstance(observation, dict) or set(observation) != {
                "schema_version",
                "python",
                "gpu_observation",
                "nvidia_smi_exit_code",
            }:
                raise ProviderSmokeError("provider smoke returned an invalid observation")
            database.mark_provider_smoke_observed(
                capability.reservation_id,
                owner_id=capability.owner_id,
                observation_json=canonical_json(observation),
                observation_sha256=sha256_json(observation),
                occurred_at=datetime.now(UTC).isoformat(),
            )
            stage = "settlement_pending"
    except Exception as exc:
        if stage in {"submission_claimed", "submitted"}:
            with suppress(DatabaseError):
                database.mark_provider_smoke_audit_blocked(
                    capability.reservation_id,
                    owner_id=capability.owner_id,
                    reason=f"{type(exc).__name__}: provider state requires audit",
                    occurred_at=datetime.now(UTC).isoformat(),
                    from_status=stage,
                )
        raise
    return {
        "action_contract_sha256": capability.action_contract_sha256,
        "reservation_id": capability.reservation_id,
        "provider_call_id": provider_call_id,
        "observation": observation,
    }
