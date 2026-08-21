from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lowbit_lab.audit import begin_attempt
from lowbit_lab.budget import BudgetGuard
from lowbit_lab.config import (
    ConfigError,
    ExperimentConfig,
    confine_experiment_config,
    load_experiment_config,
    verify_activation_authority,
    verify_sources,
)
from lowbit_lab.db import DatabaseError, ResultsDatabase, confine_results_db
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.jsonio import emit
from lowbit_lab.provenance import (
    MAX_METADATA_BYTES,
    load_metadata_policy,
    verify_metadata_repository,
)
from lowbit_lab.publication import load_manifest, scan_publication
from lowbit_lab.runtime import (
    decide_baseline_runtime,
    load_runtime_lock,
    preview_runtime_lock,
    verify_local_artifact_set,
)
from lowbit_lab.runtime_probe import run_wsl_cuda_probe

GATE_ORDER = (
    "publication",
    "config_authority",
    "zero_budget",
    "runtime_decision",
    "verified_local_runtime",
    "runtime_probe",
    "provenance",
    "evaluation_lock",
)
PREFLIGHT_GATES = GATE_ORDER[:3]
ACTION_GATES = GATE_ORDER[3:]
REUSABLE_GATES = {"provenance", "evaluation_lock"}
ZERO_STATE = {
    "weights_required": False,
    "weights_loaded": False,
    "allow_cloud_upload": False,
    "uploads_performed": False,
    "modal_submitted": False,
    "remote_submission_performed": False,
    "scheduling_enabled": False,
    "destructive_cleanup_performed": False,
    "requested_cloud_cost_usd": "0",
    "actual_cloud_cost_usd": "0",
}


class ActivationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ActivationRequest:
    config_path: Path
    db_path: Path
    publication_manifest_path: Path
    approved_plan_path: Path
    runtime_decision_path: Path
    runtime_lock_path: Path
    metadata_policy_path: Path
    evaluation_lock_path: Path
    root: Path


@dataclass(frozen=True)
class ActivationContext:
    request: ActivationRequest
    config: ExperimentConfig | None
    authority_hashes: Mapping[str, str]
    apply_authorized: bool


GateAdapter = Callable[[ActivationContext], Mapping[str, Any]]


def _unconfigured_adapter(name: str) -> GateAdapter:
    def run(_context: ActivationContext) -> Mapping[str, Any]:
        raise ActivationError(f"{name} adapter is not configured")

    return run


@dataclass(frozen=True)
class ActivationAdapters:
    runtime_decision: GateAdapter = _unconfigured_adapter("runtime_decision")
    verified_local_runtime: GateAdapter = _unconfigured_adapter("verified_local_runtime")
    runtime_probe: GateAdapter = _unconfigured_adapter("runtime_probe")
    provenance: GateAdapter = _unconfigured_adapter("provenance")
    evaluation_lock: GateAdapter = _unconfigured_adapter("evaluation_lock")
    publication: GateAdapter | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _canonical(value: object) -> tuple[str, str]:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ActivationError("gate evidence is not canonical JSON") from exc
    return encoded, hashlib.sha256(encoded.encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as exc:
        raise ActivationError("activation authority artifact is unreadable") from exc


def _confine_authority(root: Path, path: Path, prefix: str, label: str) -> Path:
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    allowed = (root / prefix).resolve()
    if not candidate.is_relative_to(allowed) or not candidate.is_file():
        raise ActivationError(f"{label} must be a file under {prefix}")
    return candidate


def _resolved_request(request: ActivationRequest) -> ActivationRequest:
    root = request.root.resolve()
    return ActivationRequest(
        root=root,
        config_path=confine_experiment_config(root, request.config_path),
        db_path=confine_results_db(root, request.db_path),
        publication_manifest_path=_confine_authority(
            root, request.publication_manifest_path, "configs/local", "publication manifest"
        ),
        approved_plan_path=_confine_authority(
            root, request.approved_plan_path, "docs/plans/local", "approved plan"
        ),
        runtime_decision_path=_confine_authority(
            root, request.runtime_decision_path, "configs/local", "runtime decision"
        ),
        runtime_lock_path=_confine_authority(
            root, request.runtime_lock_path, "configs/local", "runtime lock"
        ),
        metadata_policy_path=_confine_authority(
            root, request.metadata_policy_path, "configs/local", "metadata policy"
        ),
        evaluation_lock_path=_confine_authority(
            root, request.evaluation_lock_path, "eval/local", "evaluation lock"
        ),
    )


def _authority_and_bytes(request: ActivationRequest) -> tuple[dict[str, str], dict[str, int]]:
    runtime_lock = load_runtime_lock(request.runtime_lock_path, root=request.root)
    metadata_policy = load_metadata_policy(request.metadata_policy_path, root=request.root)
    authority = {
        "approved_plan_sha256": _file_sha256(request.approved_plan_path),
        "runtime_lock_sha256": runtime_lock.sha256,
        "metadata_policy_sha256": metadata_policy.sha256,
        "evaluation_lock_sha256": _file_sha256(request.evaluation_lock_path),
    }
    byte_caps = {
        "runtime_planned_bytes": int(preview_runtime_lock(runtime_lock)["planned_bytes"]),
        "runtime_aggregate_cap_bytes": runtime_lock.aggregate_cap_bytes,
        "metadata_inventory_cap_bytes": MAX_METADATA_BYTES,
        "metadata_aggregate_cap_bytes": metadata_policy.aggregate_bytes,
    }
    byte_caps["max_external_bytes"] = (
        byte_caps["runtime_planned_bytes"]
        + byte_caps["metadata_inventory_cap_bytes"]
        + byte_caps["metadata_aggregate_cap_bytes"]
    )
    return authority, byte_caps


def preview_activation(request: ActivationRequest) -> dict[str, Any]:
    """Build an exact plan using local reads only; this never opens or initializes SQLite."""
    request = _resolved_request(request)
    config = load_experiment_config(request.config_path, activation_preview=True)
    if config.mode != "local_activation" or config.activation is None:
        raise ConfigError("activation preview requires mode: local_activation")
    authority, byte_caps = _authority_and_bytes(request)
    paths = {
        "config": request.config_path.relative_to(request.root).as_posix(),
        "publication_manifest": request.publication_manifest_path.relative_to(
            request.root
        ).as_posix(),
        "approved_plan": request.approved_plan_path.relative_to(request.root).as_posix(),
        "runtime_decision": request.runtime_decision_path.relative_to(request.root).as_posix(),
        "runtime_lock": request.runtime_lock_path.relative_to(request.root).as_posix(),
        "metadata_policy": request.metadata_policy_path.relative_to(request.root).as_posix(),
        "evaluation_lock": request.evaluation_lock_path.relative_to(request.root).as_posix(),
    }
    return {
        "ok": True,
        "mode": "preview",
        "apply_authorized": False,
        "gates": list(GATE_ORDER),
        "authority_paths": paths,
        "declared_authority_sha256": config.activation.authority_hashes,
        "observed_authority_sha256": authority,
        "external_bytes": byte_caps,
        "runtime_decision_sha256": _file_sha256(request.runtime_decision_path),
        "stop_conditions": [
            "publication_failure",
            "authority_or_config_drift",
            "nonzero_budget",
            "runtime_not_verified_local",
            "runtime_probe_not_observed",
            "provenance_failure",
            "evaluation_lock_invalid",
            "unknown_failure",
        ],
        "side_effects_performed": False,
        **ZERO_STATE,
    }


def _publication_adapter(context: ActivationContext) -> Mapping[str, Any]:
    manifest = load_manifest(context.request.root, context.request.publication_manifest_path)
    result = scan_publication(
        context.request.root,
        public_remote=manifest.public_remote,
        protected_values=manifest.private_values,
    )
    if result.get("ok") is not True:
        raise ActivationError("publication gate failed")
    return result


def _checked_evidence(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("ok") is not True:
        raise ActivationError(f"{name} gate did not produce passing evidence")
    evidence = dict(value)
    _canonical(evidence)
    return evidence


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"{label} is unreadable or invalid JSON") from exc


def _runtime_decision_adapter(context: ActivationContext) -> Mapping[str, Any]:
    raw = _read_json(context.request.runtime_decision_path, "runtime decision")
    if not isinstance(raw, Mapping) or set(raw) != {
        "schema_version",
        "declarations",
        "measured",
    }:
        raise ActivationError("runtime decision must use the closed schema")
    if raw["schema_version"] != 1:
        raise ActivationError("runtime decision schema_version must be 1")
    decision = decide_baseline_runtime(
        declarations=raw["declarations"], measured=raw["measured"]
    )
    return {"ok": decision["status"] == "selected", **decision}


def _verified_runtime_adapter(context: ActivationContext) -> Mapping[str, Any]:
    lock = load_runtime_lock(context.request.runtime_lock_path, root=context.request.root)
    return {"ok": True, **verify_local_artifact_set(lock, root=context.request.root)}


def _runtime_probe_adapter(context: ActivationContext) -> Mapping[str, Any]:
    lock = load_runtime_lock(context.request.runtime_lock_path, root=context.request.root)
    python_path = context.request.root / lock.artifact_root / "env/bin/python"
    evidence = run_wsl_cuda_probe(
        python_path=python_path,
        root=context.request.root,
        lock_sha256=lock.sha256,
    )
    return {"ok": evidence["status"] == "observed", **evidence}


def _provenance_adapter(context: ActivationContext) -> Mapping[str, Any]:
    policy = load_metadata_policy(
        context.request.metadata_policy_path, root=context.request.root
    )
    return {
        "ok": True,
        **verify_metadata_repository(policy, root=context.request.root),
    }


def _evaluation_adapter(context: ActivationContext) -> Mapping[str, Any]:
    raw = _read_json(context.request.evaluation_lock_path, "evaluation lock")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("fixtures"), list):
        raise ActivationError("evaluation lock fixture inventory is invalid")
    fixture_root = (context.request.root / "eval/local/fixtures").resolve()
    fixture_bytes: dict[str, bytes] = {}
    for fixture in raw["fixtures"]:
        if not isinstance(fixture, Mapping):
            raise ActivationError("evaluation lock fixture is invalid")
        fixture_id = fixture.get("fixture_id")
        if (
            not isinstance(fixture_id, str)
            or Path(fixture_id).name != fixture_id
            or not fixture_id
        ):
            raise ActivationError("evaluation fixture identifier is unsafe")
        path = (fixture_root / f"{fixture_id}.json").resolve()
        if not path.is_relative_to(fixture_root):
            raise ActivationError("evaluation fixture path escapes its local root")
        try:
            fixture_bytes[fixture_id] = path.read_bytes()
        except OSError as exc:
            raise ActivationError("evaluation fixture material is missing") from exc
    pending = validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes)
    return {
        "ok": True,
        "status": pending.status,
        "evaluation_lock_sha256": pending.sha256,
        "promotion_authorized": pending.promotion_authorized,
        "candidate_execution": pending.candidate_execution,
    }


def _default_adapters() -> ActivationAdapters:
    return ActivationAdapters(
        runtime_decision=_runtime_decision_adapter,
        verified_local_runtime=_verified_runtime_adapter,
        runtime_probe=_runtime_probe_adapter,
        provenance=_provenance_adapter,
        evaluation_lock=_evaluation_adapter,
    )


def _safe_failure(exc: BaseException) -> str:
    if isinstance(exc, KeyboardInterrupt):
        return "activation interrupted in process"
    return f"{type(exc).__name__}: activation gate failed"


def _gate_bindings(config: ExperimentConfig, authority: Mapping[str, str]) -> list[dict[str, Any]]:
    _, authority_sha = _canonical(authority)
    result = []
    for order, name in enumerate(GATE_ORDER):
        _, input_sha = _canonical(
            {
                "schema_version": 1,
                "config_sha256": config.sha256,
                "gate": name,
                "preceding_gates": list(GATE_ORDER[:order]),
            }
        )
        result.append(
            {
                "gate_id": str(uuid.uuid4()),
                "name": name,
                "input_sha256": input_sha,
                "authority_sha256": authority_sha,
            }
        )
    return result


def run_activation(
    request: ActivationRequest,
    *,
    apply: bool,
    adapters: ActivationAdapters | None = None,
    clock: Callable[[], datetime] = _now,
    owner_id: str | None = None,
    lease_seconds: int = 300,
) -> dict[str, Any]:
    if not apply:
        return preview_activation(request)
    if not 1 <= lease_seconds <= 3600:
        raise ActivationError("activation lease must be between 1 and 3600 seconds")
    request = _resolved_request(request)
    database = ResultsDatabase(request.db_path)
    database.initialize()
    database.reconcile_stale_activations(now=_iso(clock()))
    attempt_id = begin_attempt(database, request.config_path, request.root, _iso(clock()))
    adapters = adapters or _default_adapters()
    owner_id = owner_id or str(uuid.uuid4())
    run_id: str | None = None
    current_gate_id: str | None = None
    linked = False
    try:
        publication = _checked_evidence(
            "publication",
            (adapters.publication or _publication_adapter)(
                ActivationContext(request, None, {}, True)
            ),
        )
        preview = preview_activation(request)
        config = load_experiment_config(request.config_path)
        authority = verify_activation_authority(
            config, preview["observed_authority_sha256"]
        )
        context = ActivationContext(request, config, authority, True)
        source_hashes = verify_sources(config, request.root)
        config_evidence = {
            "ok": True,
            "config_sha256": config.sha256,
            "source_hashes": source_hashes,
            "authority_sha256": authority,
        }
        budget = BudgetGuard(request.root / "configs/budget-policy.json")
        phase_spent, total_spent = database.spend_totals(config.phase)
        authorization = budget.authorize(
            phase=config.phase,
            requested_cost_usd=config.modal.requested_cost_usd,
            phase_spent_usd=phase_spent,
            total_spent_usd=total_spent,
        )
        budget_evidence = {
            "ok": True,
            "currency": "USD",
            "requested": format(authorization.requested, "f"),
            "phase_spent": phase_spent,
            "total_spent": total_spent,
        }
        preflight = (publication, config_evidence, budget_evidence)
        run_id = str(uuid.uuid4())
        instant = clock()
        heartbeat = _iso(instant)
        lease = _iso(instant + timedelta(seconds=lease_seconds))
        database.create_run(
            run_id=run_id,
            experiment_id=config.experiment_id,
            config_sha256=config.sha256,
            config_json=config.canonical_json,
            source_hashes=source_hashes,
            runtime={"activation": "pending"},
            hardware={"persisted": False},
            phase=config.phase,
            mode=config.mode,
            requested_cost="0",
            started_at=heartbeat,
            owner_id=owner_id,
            lease_expires_at=lease,
            heartbeat_at=heartbeat,
        )
        database.link_attempt(attempt_id, run_id, _iso(clock()))
        linked = True
        database.transition(run_id, "validated")
        database.transition(run_id, "running")
        gate_rows = _gate_bindings(config, authority)
        database.create_activation_gates(
            run_id=run_id,
            owner_id=owner_id,
            lease_expires_at=lease,
            heartbeat_at=heartbeat,
            started_at=heartbeat,
            gates=gate_rows,
        )
        for row, evidence in zip(gate_rows[:3], preflight, strict=True):
            encoded, digest = _canonical(evidence)
            database.complete_activation_gate(
                row["gate_id"],
                owner_id=owner_id,
                evidence_json=encoded,
                evidence_sha256=digest,
                ended_at=_iso(clock()),
            )
        action_adapters = {
            "runtime_decision": adapters.runtime_decision,
            "verified_local_runtime": adapters.verified_local_runtime,
            "runtime_probe": adapters.runtime_probe,
            "provenance": adapters.provenance,
            "evaluation_lock": adapters.evaluation_lock,
        }
        for order, row in enumerate(gate_rows[3:], start=3):
            current_gate_id = row["gate_id"]
            reusable = None
            if row["name"] in REUSABLE_GATES:
                reusable = database.find_reusable_activation_gate(
                    name=row["name"],
                    input_sha256=row["input_sha256"],
                    authority_sha256=row["authority_sha256"],
                )
            if reusable is not None:
                database.complete_activation_gate(
                    current_gate_id,
                    owner_id=owner_id,
                    evidence_json=reusable["evidence_json"],
                    evidence_sha256=reusable["evidence_sha256"],
                    ended_at=_iso(clock()),
                    reused_gate_id=reusable["gate_id"],
                )
                continue
            database.invalidate_activation_evidence(
                experiment_id=config.experiment_id,
                from_order=order,
                input_sha256=row["input_sha256"],
                authority_sha256=row["authority_sha256"],
                reason="activation binding drift",
                invalidated_at=_iso(clock()),
                current_run_id=run_id,
            )
            instant = clock()
            database.start_activation_gate(
                current_gate_id,
                owner_id=owner_id,
                heartbeat_at=_iso(instant),
                lease_expires_at=_iso(instant + timedelta(seconds=lease_seconds)),
            )
            evidence = _checked_evidence(row["name"], action_adapters[row["name"]](context))
            encoded, digest = _canonical(evidence)
            database.complete_activation_gate(
                current_gate_id,
                owner_id=owner_id,
                evidence_json=encoded,
                evidence_sha256=digest,
                ended_at=_iso(clock()),
            )
        for name, value in ZERO_STATE.items():
            database.add_metric(run_id, name, value)
        evaluation = database.get_activation_gates(run_id)[-1]["evidence"]
        database.add_metric(
            run_id, "promotion_authorized", evaluation.get("promotion_authorized") is True
        )
        database.transition(run_id, "completed", ended_at=_iso(clock()))
    except BaseException as exc:
        reason = _safe_failure(exc)
        ended = _iso(clock())
        attempt = database.get_attempt(attempt_id)
        if attempt["status"] == "received":
            database.fail_attempt(attempt_id, reason, ended)
        if run_id is not None:
            if current_gate_id is not None:
                with suppress(DatabaseError):
                    database.fail_activation_gate(
                        current_gate_id, owner_id=owner_id, reason=reason, ended_at=ended
                    )
            database.fail_remaining_activation_gates(
                run_id, owner_id=owner_id, reason="preceding activation gate failed", ended_at=ended
            )
            with suppress(DatabaseError):
                database.transition(run_id, "failed", reason=reason, ended_at=ended)
        raise
    assert run_id is not None and linked
    return {
        "ok": True,
        "attempt_id": attempt_id,
        "run": database.get_run(run_id),
        "gates": database.get_activation_gates(run_id),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview or run local activation gates")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path("results/local/activation.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--publication-manifest", type=Path, required=True)
    parser.add_argument("--approved-plan", type=Path, required=True)
    parser.add_argument("--runtime-decision", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--metadata-policy", type=Path, required=True)
    parser.add_argument("--evaluation-lock", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    request = ActivationRequest(
        config_path=args.config,
        db_path=args.db,
        publication_manifest_path=args.publication_manifest,
        approved_plan_path=args.approved_plan,
        runtime_decision_path=args.runtime_decision,
        runtime_lock_path=args.runtime_lock,
        metadata_policy_path=args.metadata_policy,
        evaluation_lock_path=args.evaluation_lock,
        root=args.root,
    )
    try:
        emit(run_activation(request, apply=args.apply))
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        emit({"ok": False, "error": type(exc).__name__, "message": _safe_failure(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
