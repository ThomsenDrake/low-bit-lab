from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from lowbit_lab.audit import begin_attempt, failure_reason
from lowbit_lab.budget import BudgetGuard, ReferenceBudgetGuard
from lowbit_lab.config import (
    IMMUTABLE_REVISION_RE,
    SHA256_RE,
    ConfigError,
    confine_experiment_config,
    load_experiment_config,
    verify_sources,
)
from lowbit_lab.db import ResultsDatabase, confine_results_db
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.jsonio import emit
from lowbit_lab.provenance import parse_weight_inventory
from lowbit_lab.reference_contract import REFERENCE_RESOURCES
from lowbit_lab.reference_gates import (
    ReferenceGateError,
    verify_cold_path_time_evidence,
    verify_formula_authority,
    verify_memory_fit_evidence,
    verify_provider_safety_evidence,
)
from lowbit_lab.runtime import (
    hardware_metadata,
    load_runtime_lock,
    runtime_metadata,
    verify_current_installed_environment,
)

REFERENCE_FIELDS = {
    "schema_version",
    "kind",
    "experiment_id",
    "approved_plan_path",
    "approved_plan_sha256",
    "budget_policy_path",
    "inputs",
    "authority_files",
    "resources",
    "provider",
    "gates",
    "approval_artifact_path",
}


class ReferenceJobError(ValueError):
    pass


@dataclass(frozen=True)
class ReferenceJobConfig:
    experiment_id: str
    approved_plan_path: str
    approved_plan_sha256: str
    budget_policy_path: str
    inputs: dict[str, str | int | None]
    authority_files: dict[str, str | None]
    resources: dict[str, object]
    provider: dict[str, object]
    gates: dict[str, str | None]
    approval_artifact_path: str | None
    canonical_json: str
    sha256: str
    challenge_sha256: str


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReferenceJobError(f"{label} schema is closed")
    return value


def _repo_path(root: Path, value: Any, label: str, prefix: str) -> str:
    if not isinstance(value, str):
        raise ReferenceJobError(f"{label} must be a repository-relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.as_posix().startswith(prefix):
        raise ReferenceJobError(f"{label} must stay under {prefix}")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ReferenceJobError(f"{label} resolves outside repository")
    return path.as_posix()


def _reject_credential_fields(value: Any, *, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            credential_like = (
                lowered in {"password", "passwd", "credential", "token", "secret", "api_key"}
                or lowered.endswith(
                    ("_password", "_passwd", "_credential", "_token", "_secret", "_api_key")
                )
            )
            if key not in {"secrets", "credentials_source"} and credential_like:
                raise ReferenceJobError(f"credential-like field is forbidden: {path}.{key}")
            _reject_credential_fields(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_credential_fields(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and any(
        pattern.search(value)
        for pattern in (
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b"),
            re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        )
    ):
        raise ReferenceJobError(f"credential-shaped value is forbidden: {path}")


def _file_sha256(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as exc:
        raise ReferenceJobError(f"cannot hash authority input: {path.name}") from exc


def load_reference_job_config(path: Path, *, root: Path) -> ReferenceJobConfig:
    root = root.resolve()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReferenceJobError(f"cannot read reference config: {exc}") from exc
    _reject_credential_fields(raw)
    top = _closed(raw, REFERENCE_FIELDS, "reference config")
    if top["schema_version"] != 1 or top["kind"] != "modal_reference_preview":
        raise ReferenceJobError("unsupported reference config")
    if not isinstance(top["experiment_id"], str) or not top["experiment_id"]:
        raise ReferenceJobError("reference experiment_id is required")
    plan_path = _repo_path(
        root, top["approved_plan_path"], "approved_plan_path", "docs/plans/local/"
    )
    plan_sha = top["approved_plan_sha256"]
    if not isinstance(plan_sha, str) or SHA256_RE.fullmatch(plan_sha) is None:
        raise ReferenceJobError("approved_plan_sha256 must be lowercase SHA-256")
    if _file_sha256(root / plan_path) != plan_sha:
        raise ReferenceJobError("approved plan hash mismatch")
    budget_path = _repo_path(
        root, top["budget_policy_path"], "budget_policy_path", "configs/local/"
    )
    input_fields = {
        "weight_inventory_sha256",
        "weight_inventory_tensor_bytes",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "evaluation_lock_sha256",
        "evaluation_max_context_tokens",
        "formula_authority_sha256",
        "reviewed_commit_sha256",
        "control_plane_sha256",
    }
    inputs = _closed(top["inputs"], input_fields, "reference inputs")
    for name, digest in inputs.items():
        if name in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}:
            if not isinstance(digest, int) or isinstance(digest, bool) or digest <= 0:
                raise ReferenceJobError(f"{name} must be positive")
            continue
        if digest is None and name == "formula_authority_sha256":
            continue
        if name == "reviewed_commit_sha256":
            if not isinstance(digest, str) or IMMUTABLE_REVISION_RE.fullmatch(digest) is None:
                raise ReferenceJobError("reviewed_commit_sha256 must be a commit identity")
            continue
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ReferenceJobError(f"{name} must be lowercase SHA-256")
    authority_fields = {
        "weight_inventory_path": "artifacts/local/",
        "source_shard_metadata_path": "artifacts/local/",
        "provenance_manifest_path": "artifacts/local/",
        "runtime_lock_path": "configs/local/",
        "runtime_receipt_path": "artifacts/local/",
        "evaluation_lock_path": "eval/local/",
        "evaluation_fixture_root": "eval/local/",
    }
    authority_files = _closed(top["authority_files"], set(authority_fields), "authority files")
    if any(value is None for value in authority_files.values()):
        if not all(value is None for value in authority_files.values()):
            raise ReferenceJobError("reference authority file paths are all-or-none")
    else:
        for name, prefix in authority_fields.items():
            authority_files[name] = _repo_path(root, authority_files[name], name, prefix)
    resources = _closed(top["resources"], set(REFERENCE_RESOURCES), "reference resources")
    if resources != REFERENCE_RESOURCES:
        raise ReferenceJobError("reference resource envelope does not match approval plan")
    provider_fields = {
        "submit",
        "scheduling_enabled",
        "cloud_upload",
        "mounts",
        "volumes",
        "secrets",
        "credentials_source",
        "safety_evidence_path",
        "safety_evidence_sha256",
    }
    provider = _closed(top["provider"], provider_fields, "reference provider")
    if provider["submit"] is not False:
        raise ReferenceJobError("reference submission remains disabled")
    if (
        provider["scheduling_enabled"] is not False
        or provider["cloud_upload"] is not False
        or provider["mounts"] != []
        or provider["volumes"] != []
        or provider["secrets"] != []
        or provider["credentials_source"] != "provider_local"
    ):
        raise ReferenceJobError("reference provider violates the private-data boundary")
    evidence_path = provider["safety_evidence_path"]
    evidence_sha = provider["safety_evidence_sha256"]
    if (evidence_path is None) != (evidence_sha is None):
        raise ReferenceJobError("provider evidence path and SHA-256 must be supplied together")
    if evidence_path is not None:
        provider["safety_evidence_path"] = _repo_path(
            root, evidence_path, "safety_evidence_path", "reports/local/"
        )
        if not isinstance(evidence_sha, str) or SHA256_RE.fullmatch(evidence_sha) is None:
            raise ReferenceJobError("safety_evidence_sha256 must be lowercase SHA-256")
    gates = _closed(
        top["gates"],
        {
            "formula_authority_path",
            "memory_fit_evidence_path",
            "memory_fit_evidence_sha256",
            "cold_path_time_evidence_path",
            "cold_path_time_evidence_sha256",
        },
        "reference gates",
    )
    for path_name, digest_name in (
        ("memory_fit_evidence_path", "memory_fit_evidence_sha256"),
        ("cold_path_time_evidence_path", "cold_path_time_evidence_sha256"),
    ):
        evidence_path = gates[path_name]
        evidence_digest = gates[digest_name]
        if (evidence_path is None) != (evidence_digest is None):
            raise ReferenceJobError("reference gate path and SHA-256 must be supplied together")
        if evidence_path is not None:
            gates[path_name] = _repo_path(root, evidence_path, path_name, "reports/local/")
            if not isinstance(evidence_digest, str) or SHA256_RE.fullmatch(evidence_digest) is None:
                raise ReferenceJobError(f"{digest_name} must be lowercase SHA-256")
    formula_path = gates["formula_authority_path"]
    formula_sha = inputs["formula_authority_sha256"]
    if (formula_path is None) != (formula_sha is None):
        raise ReferenceJobError(
            "formula authority path and SHA-256 must be supplied together"
        )
    if formula_path is not None:
        gates["formula_authority_path"] = _repo_path(
            root,
            formula_path,
            "formula_authority_path",
            "reports/local/",
        )
    approval_path = top["approval_artifact_path"]
    if approval_path is not None:
        approval_path = _repo_path(
            root, approval_path, "approval_artifact_path", "configs/local/"
        )
    canonical = json.dumps(top, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    challenge_material = {
        key: value for key, value in top.items() if key != "approval_artifact_path"
    }
    challenge_json = json.dumps(
        challenge_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return ReferenceJobConfig(
        experiment_id=top["experiment_id"],
        approved_plan_path=plan_path,
        approved_plan_sha256=plan_sha,
        budget_policy_path=budget_path,
        inputs=dict(inputs),
        authority_files=dict(authority_files),
        resources=dict(resources),
        provider=dict(provider),
        gates=dict(gates),
        approval_artifact_path=approval_path,
        canonical_json=canonical,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        challenge_sha256=hashlib.sha256(challenge_json.encode()).hexdigest(),
    )


def plan_reference_preview(config: ReferenceJobConfig, *, root: Path) -> dict[str, object]:
    budget = ReferenceBudgetGuard(
        root / config.budget_policy_path,
        expected_plan_sha256=config.approved_plan_sha256,
    )
    budget_preview = budget.preview(
        cpu_cores=int(config.resources["cpu_cores"]),
        memory_gib=int(config.resources["memory_gib"]),
        wall_clock_seconds=int(config.resources["timeout_seconds"]),
    )
    blockers: list[str] = []
    if not _verify_reference_authorities(config, root=root):
        blockers.append("authority_artifacts_unverified")
    current_runtime = runtime_metadata(root)
    if current_runtime["git_dirty"]:
        blockers.append("review_tree_dirty")
    if current_runtime["git_commit"] != config.inputs["reviewed_commit_sha256"]:
        blockers.append("reviewed_commit_mismatch")
    if current_runtime["control_plane_sha256"] != config.inputs["control_plane_sha256"]:
        blockers.append("control_plane_hash_mismatch")
    formula_verified = False
    formula_human_approved = False
    formula_sha = config.inputs["formula_authority_sha256"]
    formula_path = config.gates["formula_authority_path"]
    if isinstance(formula_sha, str) and isinstance(formula_path, str):
        try:
            formula_result = verify_formula_authority(
                root / formula_path,
                expected_sha256=formula_sha,
                expected_maximum_context_tokens=int(
                    config.inputs["evaluation_max_context_tokens"]
                ),
                expected_timeout_seconds=int(config.resources["timeout_seconds"]),
            )
            formula_verified = bool(formula_result["verified"])
            formula_human_approved = bool(formula_result["human_approved"])
        except ReferenceGateError:
            formula_verified = False
    if formula_sha is None:
        blockers.append("formula_authority_missing")
    elif not formula_verified:
        blockers.append("formula_authority_unverified")
    elif not formula_human_approved:
        blockers.append("formula_authority_review_pending")
    provider_safety_proven = False
    provider_path = config.provider["safety_evidence_path"]
    provider_sha = config.provider["safety_evidence_sha256"]
    if isinstance(provider_path, str) and isinstance(provider_sha, str):
        try:
            provider_safety_proven = bool(
                verify_provider_safety_evidence(
                    root / provider_path, expected_sha256=provider_sha
                )["proven"]
            )
        except ReferenceGateError:
            provider_safety_proven = False
    if not provider_safety_proven:
        blockers.extend(
            [
                "provider_workspace_cap_unproven",
                "provider_billing_attribution_unproven",
                "provider_crash_rescheduling_unbounded",
            ]
        )
    memory_fit_proven = False
    memory_path = config.gates["memory_fit_evidence_path"]
    memory_sha = config.gates["memory_fit_evidence_sha256"]
    verified_formula_sha = formula_sha if formula_verified else None
    if (
        isinstance(memory_path, str)
        and isinstance(memory_sha, str)
        and isinstance(verified_formula_sha, str)
    ):
        try:
            memory_fit_proven = verify_memory_fit_evidence(
                root / memory_path,
                expected_sha256=memory_sha,
                expected_inventory_sha256=str(config.inputs["weight_inventory_sha256"]),
                expected_tensor_bytes=int(config.inputs["weight_inventory_tensor_bytes"]),
                expected_method_sha256=verified_formula_sha,
                expected_evaluation_lock_sha256=str(
                    config.inputs["evaluation_lock_sha256"]
                ),
                expected_maximum_context_tokens=int(
                    config.inputs["evaluation_max_context_tokens"]
                ),
            ).proven
        except ReferenceGateError:
            memory_fit_proven = False
    if not memory_fit_proven:
        blockers.append("memory_fit_unproven")
    time_budget_proven = False
    time_path = config.gates["cold_path_time_evidence_path"]
    time_sha = config.gates["cold_path_time_evidence_sha256"]
    if (
        isinstance(time_path, str)
        and isinstance(time_sha, str)
        and isinstance(verified_formula_sha, str)
    ):
        try:
            time_budget_proven = verify_cold_path_time_evidence(
                root / time_path,
                expected_sha256=time_sha,
                timeout_seconds=int(config.resources["timeout_seconds"]),
                expected_method_sha256=verified_formula_sha,
                expected_evaluation_lock_sha256=str(
                    config.inputs["evaluation_lock_sha256"]
                ),
            ).proven
        except ReferenceGateError:
            time_budget_proven = False
    if not time_budget_proven:
        blockers.append("cold_path_time_budget_unproven")
    approval_valid = False
    if config.approval_artifact_path is not None:
        try:
            approval = validate_reference_approval(
                root / config.approval_artifact_path,
                expected_challenge_sha256=config.challenge_sha256,
                now=datetime.now(UTC),
            )
            approval_valid = approval["reviewed_commit_sha256"] == config.inputs[
                "reviewed_commit_sha256"
            ]
        except ReferenceJobError:
            approval_valid = False
    if not approval_valid:
        blockers.append("execution_approval_missing")
    return {
        "schema_version": 1,
        "kind": "modal_reference_preview",
        "submit": False,
        "scheduling_enabled": False,
        "cloud_upload": False,
        "weights_transferred": False,
        "actual_cost_usd": "0",
        "maximum_cost_usd": format(budget_preview.maximum_cost_usd, "f"),
        "estimated_cost_usd": format(budget_preview.estimated_cost_usd, "f"),
        "resources": config.resources,
        "challenge_sha256": config.challenge_sha256,
        "config_sha256": config.sha256,
        "blockers": blockers,
    }


def _verify_reference_authorities(config: ReferenceJobConfig, *, root: Path) -> bool:
    if any(value is None for value in config.authority_files.values()):
        return False
    try:
        paths = {name: root / str(value) for name, value in config.authority_files.items()}
        provenance = json.loads(paths["provenance_manifest_path"].read_text(encoding="utf-8"))
        if provenance["manifest_sha256"] != config.inputs["provenance_manifest_sha256"]:
            return False
        index_entry = next(
            item for item in provenance["files"] if item["path"] == "model.safetensors.index.json"
        )
        tokenizer_entry = next(
            item for item in provenance["files"] if item["path"] == "tokenizer.json"
        )
        index_bytes = (root / index_entry["local_content"]["cache_path"]).read_bytes()
        source_metadata = json.loads(
            paths["source_shard_metadata_path"].read_text(encoding="utf-8")
        )
        source_shards = {
            name: (item["size_bytes"], item["lfs_sha256"])
            for name, item in source_metadata.items()
        }
        inventory_raw = json.loads(
            paths["weight_inventory_path"].read_text(encoding="utf-8")
        )
        runtime_lock = load_runtime_lock(paths["runtime_lock_path"], root=root)
        evaluation_raw = json.loads(paths["evaluation_lock_path"].read_text(encoding="utf-8"))
        fixture_root = paths["evaluation_fixture_root"]
        fixture_bytes = {
            fixture["fixture_id"]: (
                fixture_root / f"{fixture['fixture_id']}.json"
            ).read_bytes()
            for fixture in evaluation_raw["fixtures"]
        }
        evaluation_lock = validate_pending_evaluation_lock(
            evaluation_raw, fixture_bytes=fixture_bytes
        )
        expected_bindings = {
            "provenance_manifest_sha256": config.inputs["provenance_manifest_sha256"],
            "tokenizer_sha256": tokenizer_entry["local_content"]["sha256"],
            "runtime_lock_sha256": runtime_lock.sha256,
            "evaluation_lock_sha256": evaluation_lock.sha256,
            "source_index_sha256": hashlib.sha256(index_bytes).hexdigest(),
        }
        inventory = parse_weight_inventory(
            inventory_raw,
            source_index_bytes=index_bytes,
            source_shards=source_shards,
            expected_bindings=expected_bindings,
        )
        if (
            inventory.sha256 != config.inputs["weight_inventory_sha256"]
            or inventory.index_tensor_bytes != config.inputs["weight_inventory_tensor_bytes"]
        ):
            return False
        receipt = json.loads(paths["runtime_receipt_path"].read_text(encoding="utf-8"))
        verified = verify_current_installed_environment(receipt, root=root, lock=runtime_lock)
        return verified["receipt_sha256"] == config.inputs["runtime_receipt_sha256"]
    except (KeyError, OSError, TypeError, ValueError, StopIteration):
        return False


def redact_provider_output(value: str, *, maximum_chars: int = 4096) -> str:
    """Bound provider diagnostics and remove credential-shaped assignments."""
    redacted = value
    patterns = (
        r"(?i)([\"']?modal_token_id[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
        r"(?i)([\"']?modal_token_secret[\"']?\s*[=:]\s*[\"']?)[^\s,;\"']+",
        r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|password|secret)[\"']?"
        r"\s*[=:]\s*[\"']?)[^\s,;\"']+",
        r"(?i)(Authorization\s*[=:]\s*(?:Bearer\s+)?)[^\s,;]+",
        r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
    )
    for pattern in patterns:
        redacted = re.sub(
            pattern,
            lambda match: f"{match.group(1)}[REDACTED]"
            if match.lastindex
            else "[REDACTED]",
            redacted,
        )
    return redacted[:maximum_chars]


def validate_reference_approval(
    path: Path, *, expected_challenge_sha256: str, now: datetime
) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceJobError(f"cannot read reference approval: {exc}") from exc
    fields = {
        "schema_version",
        "kind",
        "challenge_sha256",
        "reviewed_commit_sha256",
        "maximum_cost_usd",
        "expires_at",
    }
    approval = _closed(raw, fields, "reference approval")
    if approval["schema_version"] != 1 or approval["kind"] != "reference_execution_approval":
        raise ReferenceJobError("unsupported reference approval")
    if approval["challenge_sha256"] != expected_challenge_sha256:
        raise ReferenceJobError("reference approval challenge mismatch")
    if IMMUTABLE_REVISION_RE.fullmatch(str(approval["reviewed_commit_sha256"])) is None:
        raise ReferenceJobError("reference approval commit is invalid")
    if approval["maximum_cost_usd"] != "4.00":
        raise ReferenceJobError("reference approval cost cap is invalid")
    try:
        expires_at = datetime.fromisoformat(approval["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ReferenceJobError("reference approval expiry is invalid") from exc
    if expires_at.tzinfo is None or now >= expires_at:
        raise ReferenceJobError("reference approval is expired")
    canonical = json.dumps(approval, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "challenge_sha256": approval["challenge_sha256"],
        "approval_digest": hashlib.sha256(canonical.encode()).hexdigest(),
        "expires_at": approval["expires_at"],
        "reviewed_commit_sha256": approval["reviewed_commit_sha256"],
    }


def plan_reference_dry_run(
    config_path: Path, db_path: Path, root: Path
) -> dict[str, object]:
    root = root.resolve()
    db_path = confine_results_db(root, db_path)
    database = ResultsDatabase(db_path)
    database.initialize()
    config_path = confine_experiment_config(root, config_path)
    started_at = _now()
    attempt_id = begin_attempt(database, config_path, root, started_at)
    run_id: str | None = None
    try:
        config = load_reference_job_config(config_path, root=root)
        job_plan = plan_reference_preview(config, root=root)
        run_id = str(uuid.uuid4())
        database.create_run(
            run_id=run_id,
            experiment_id=config.experiment_id,
            config_sha256=config.sha256,
            config_json=config.canonical_json,
            source_hashes={
                name: digest for name, digest in config.inputs.items() if digest is not None
            },
            runtime={"receipt_sha256": config.inputs["runtime_receipt_sha256"]},
            hardware=hardware_metadata(),
            phase=1,
            mode="modal_dry_run",
            requested_cost="0",
            started_at=started_at,
            attempt_id=attempt_id,
        )
        database.transition(run_id, "validated")
        database.transition(run_id, "running")
        database.add_metric(run_id, "reference_job_plan", job_plan)
        database.add_metric(run_id, "modal_submitted", False)
        database.add_metric(run_id, "weights_transferred", False)
        database.add_metric(run_id, "promotion_authorized", False)
        database.transition(run_id, "completed", ended_at=_now())
    except Exception as exc:
        attempt = database.get_attempt(attempt_id)
        if attempt["status"] == "received":
            database.fail_attempt(attempt_id, failure_reason(exc), _now())
        elif run_id is not None:
            database.transition(run_id, "failed", reason=failure_reason(exc), ended_at=_now())
        raise
    return {
        "ok": True,
        "attempt_id": attempt_id,
        "job_plan": job_plan,
        "run": database.get_run(run_id),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def plan_modal_dry_run(
    config_path: Path, db_path: Path, root: Path, *, dry_run: bool
) -> dict[str, object]:
    if not dry_run:
        raise ConfigError("Modal submission is not implemented or authorized; pass --dry-run")
    root = root.resolve()
    db_path = confine_results_db(root, db_path)
    database = ResultsDatabase(db_path)
    database.initialize()
    config_path = confine_experiment_config(root, config_path)
    attempt_id = begin_attempt(database, config_path, root, _now())
    run_id: str | None = None
    try:
        config = load_experiment_config(config_path)
        if config.mode != "modal_dry_run":
            raise ConfigError("Modal wrapper requires mode: modal_dry_run")
        source_hashes = verify_sources(config, root)
        guard = BudgetGuard(root / "configs" / "budget-policy.json")
        phase_spent, total_spent = database.spend_totals(config.phase)
        authorization = guard.authorize(
            phase=config.phase,
            requested_cost_usd=config.modal.requested_cost_usd,
            phase_spent_usd=phase_spent,
            total_spent_usd=total_spent,
        )
        derived_max_cost = guard.estimate_h100_cost(
            config.modal.gpu_count, config.modal.wall_clock_seconds
        )
        if derived_max_cost > authorization.requested:
            raise ConfigError("resource-derived maximum cost exceeds the requested budget cap")
        job_plan = {
            "submit": False,
            "dry_run": True,
            "phase": config.phase,
            "budget_cap_usd": str(authorization.requested),
            "resource_derived_max_cost_usd": str(derived_max_cost),
            "gpu_type": config.modal.gpu_type,
            "gpu_count": config.modal.gpu_count,
            "wall_clock_seconds": config.modal.wall_clock_seconds,
            "checkpoint_path": config.modal.checkpoint_path,
            "cleanup": config.modal.cleanup,
            "cloud_upload": False,
            "weights_required": False,
            "stop_conditions": [
                "budget_cap_reached",
                "wall_clock_reached",
                "checkpoint_failure",
                "unknown_failure_mode",
            ],
        }
        run_id = str(uuid.uuid4())
        database.create_run(
            run_id=run_id,
            experiment_id=config.experiment_id,
            config_sha256=config.sha256,
            config_json=config.canonical_json,
            source_hashes=source_hashes,
            runtime=runtime_metadata(root, config.runtime_name, config.runtime_revision),
            hardware=hardware_metadata(),
            phase=config.phase,
            mode=config.mode,
            requested_cost=str(authorization.requested),
            started_at=_now(),
        )
        database.link_attempt(attempt_id, run_id, _now())
        database.transition(run_id, "validated")
        database.transition(run_id, "running")
        database.add_metric(run_id, "modal_job_plan", job_plan)
        database.add_metric(run_id, "modal_submitted", False)
        database.transition(run_id, "completed", ended_at=_now())
    except Exception as exc:
        attempt = database.get_attempt(attempt_id)
        if attempt["status"] == "received":
            database.fail_attempt(attempt_id, failure_reason(exc), _now())
        elif run_id is not None:
            database.transition(run_id, "failed", reason=failure_reason(exc), ended_at=_now())
        raise
    return {
        "ok": True,
        "attempt_id": attempt_id,
        "job_plan": job_plan,
        "run": database.get_run(run_id),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path("results/results.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        config_path = confine_experiment_config(args.root.resolve(), args.config)
        try:
            raw_text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config: {exc}") from exc
        if re.search(r"(?m)^kind:\s*modal_reference_preview\s*$", raw_text):
            emit(plan_reference_dry_run(args.config, args.db, args.root.resolve()))
        else:
            emit(
                plan_modal_dry_run(
                    args.config, args.db, args.root.resolve(), dry_run=args.dry_run
                )
            )
    except Exception as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
