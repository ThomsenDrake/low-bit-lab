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
from lowbit_lab.provider_evidence import (
    ProviderEvidenceError,
    validate_provider_capability_receipt,
)
from lowbit_lab.publication import PublicationError, load_manifest, scan_publication
from lowbit_lab.reference_authority import (
    AUTHORITY_PATH,
    BOOTSTRAP_AUTHORITY_PATH,
    ReferenceAuthorityError,
    validate_reference_authority,
    validate_reference_bootstrap_authority,
)
from lowbit_lab.reference_bootstrap import (
    EMPIRICAL_FACTS,
    ReferenceBootstrapError,
    validate_bootstrap_request_bytes,
    validate_image_lock_bytes,
    validate_request_image_lock,
)
from lowbit_lab.reference_contract import (
    APPROVED_PROVIDER_AMENDMENT_PATH,
    APPROVED_PROVIDER_AMENDMENT_SHA256,
    APPROVED_TRUST_OVERRIDE_PLAN_PATH,
    APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
    APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256,
    ORIGINAL_APPROVED_PLAN_PATH,
    ORIGINAL_APPROVED_PLAN_SHA256,
    PROVIDER_APPROVAL_OBSERVATION_MAX_AGE_SECONDS,
    REFERENCE_RESOURCES,
    reference_execution_scope_sha256,
)
from lowbit_lab.reference_evidence import (
    ReferenceEvidenceError,
    verify_cold_path_evidence_reproducible,
    verify_memory_evidence_reproducible,
)
from lowbit_lab.reference_gates import (
    ReferenceGateError,
    verify_cold_path_time_evidence,
    verify_formula_approval_receipt,
    verify_formula_authority,
    verify_memory_fit_evidence,
    verify_provider_billing_authority,
    verify_provider_constraint_contract,
    verify_provider_observation_receipt,
    verify_provider_observation_receipt_for_trust_override,
    verify_provider_observation_trust_override,
)
from lowbit_lab.runtime import (
    RuntimeLock,
    hardware_metadata,
    load_runtime_lock,
    runtime_metadata,
    verify_current_installed_environment,
)

REFERENCE_FIELDS = {
    "schema_version",
    "kind",
    "experiment_id",
    "original_approved_plan_path",
    "original_approved_plan_sha256",
    "approved_amendment_path",
    "approved_amendment_sha256",
    "approved_trust_override_plan_path",
    "approved_trust_override_plan_sha256",
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
    original_approved_plan_path: str
    original_approved_plan_sha256: str
    approved_amendment_path: str
    approved_amendment_sha256: str
    approved_trust_override_plan_path: str
    approved_trust_override_plan_sha256: str
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

    @property
    def reference_execution_scope_sha256(self) -> str | None:
        formula_authority_sha256 = self.inputs["formula_authority_sha256"]
        formula_approval_sha256 = self.gates["formula_approval_sha256"]
        if formula_authority_sha256 is None or formula_approval_sha256 is None:
            return None
        return reference_execution_scope_sha256(
            source_revision=str(self.inputs["source_revision"]),
            weight_inventory_sha256=str(self.inputs["weight_inventory_sha256"]),
            evaluation_lock_sha256=str(self.inputs["evaluation_lock_sha256"]),
            formula_authority_sha256=str(formula_authority_sha256),
            formula_approval_sha256=str(formula_approval_sha256),
            trust_override_sha256=self.provider["trust_override_sha256"],
        )


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
            credential_like = lowered in {
                "password",
                "passwd",
                "credential",
                "token",
                "secret",
                "api_key",
            } or lowered.endswith(
                ("_password", "_passwd", "_credential", "_token", "_secret", "_api_key")
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


def _now_datetime() -> datetime:
    return datetime.now(UTC)


def load_reference_job_config(path: Path, *, root: Path) -> ReferenceJobConfig:
    root = root.resolve()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReferenceJobError(f"cannot read reference config: {exc}") from exc
    _reject_credential_fields(raw)
    top = _closed(raw, REFERENCE_FIELDS, "reference config")
    if top["schema_version"] != 5 or top["kind"] != "modal_reference_preview":
        raise ReferenceJobError("unsupported reference config")
    if not isinstance(top["experiment_id"], str) or not top["experiment_id"]:
        raise ReferenceJobError("reference experiment_id is required")
    original_plan_path = _repo_path(
        root,
        top["original_approved_plan_path"],
        "original_approved_plan_path",
        "docs/plans/local/",
    )
    original_plan_sha = top["original_approved_plan_sha256"]
    if original_plan_path != ORIGINAL_APPROVED_PLAN_PATH:
        raise ReferenceJobError("original approved plan path is not accepted")
    if original_plan_sha != ORIGINAL_APPROVED_PLAN_SHA256:
        raise ReferenceJobError("original approved plan hash is not accepted")
    if _file_sha256(root / original_plan_path) != original_plan_sha:
        raise ReferenceJobError("original approved plan hash mismatch")
    amendment_path = _repo_path(
        root,
        top["approved_amendment_path"],
        "approved_amendment_path",
        "docs/plans/local/",
    )
    amendment_sha = top["approved_amendment_sha256"]
    if amendment_path != APPROVED_PROVIDER_AMENDMENT_PATH:
        raise ReferenceJobError("approved amendment path is not accepted")
    if amendment_sha != APPROVED_PROVIDER_AMENDMENT_SHA256:
        raise ReferenceJobError("approved amendment hash is not accepted")
    if _file_sha256(root / amendment_path) != amendment_sha:
        raise ReferenceJobError("approved amendment hash mismatch")
    trust_plan_path = _repo_path(
        root,
        top["approved_trust_override_plan_path"],
        "approved_trust_override_plan_path",
        "docs/plans/local/",
    )
    trust_plan_sha = top["approved_trust_override_plan_sha256"]
    if trust_plan_path != APPROVED_TRUST_OVERRIDE_PLAN_PATH:
        raise ReferenceJobError("approved trust override plan path is not accepted")
    if trust_plan_sha != APPROVED_TRUST_OVERRIDE_PLAN_SHA256:
        raise ReferenceJobError("approved trust override plan hash is not accepted")
    if _file_sha256(root / trust_plan_path) != trust_plan_sha:
        raise ReferenceJobError("approved trust override plan hash mismatch")
    budget_path = _repo_path(
        root, top["budget_policy_path"], "budget_policy_path", "configs/local/"
    )
    input_fields = {
        "source_revision",
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
        if name in {"source_revision", "reviewed_commit_sha256"}:
            if not isinstance(digest, str) or IMMUTABLE_REVISION_RE.fullmatch(digest) is None:
                raise ReferenceJobError(f"{name} must be a commit identity")
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
        "workspace_scope_sha256",
        "environment_scope_sha256",
        "constraint_contract_path",
        "constraint_contract_sha256",
        "observation_receipt_path",
        "observation_receipt_sha256",
        "observation_screenshot_sha256",
        "trust_override_path",
        "trust_override_sha256",
        "human_approval_statement_sha256",
        "billing_authority_path",
        "billing_authority_sha256",
        "authoritative_report_identity_sha256",
        "billing_completeness_delay_seconds",
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
    for digest_name in ("workspace_scope_sha256", "environment_scope_sha256"):
        digest = provider[digest_name]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ReferenceJobError(f"{digest_name} must be lowercase SHA-256")
    if (
        not isinstance(provider["observation_screenshot_sha256"], str)
        or SHA256_RE.fullmatch(provider["observation_screenshot_sha256"]) is None
    ):
        raise ReferenceJobError("observation_screenshot_sha256 must be lowercase SHA-256")
    if (
        not isinstance(provider["authoritative_report_identity_sha256"], str)
        or SHA256_RE.fullmatch(provider["authoritative_report_identity_sha256"]) is None
    ):
        raise ReferenceJobError("authoritative_report_identity_sha256 must be lowercase SHA-256")
    if (
        not isinstance(provider["billing_completeness_delay_seconds"], int)
        or isinstance(provider["billing_completeness_delay_seconds"], bool)
        or provider["billing_completeness_delay_seconds"] <= 0
    ):
        raise ReferenceJobError("billing_completeness_delay_seconds must be positive")
    for path_name, digest_name in (
        ("constraint_contract_path", "constraint_contract_sha256"),
        ("observation_receipt_path", "observation_receipt_sha256"),
        ("billing_authority_path", "billing_authority_sha256"),
        ("trust_override_path", "trust_override_sha256"),
    ):
        evidence_path = provider[path_name]
        evidence_sha = provider[digest_name]
        if (evidence_path is None) != (evidence_sha is None):
            raise ReferenceJobError(f"{path_name} and {digest_name} must be supplied together")
        if evidence_path is not None:
            provider[path_name] = _repo_path(root, evidence_path, path_name, "reports/local/")
            if not isinstance(evidence_sha, str) or SHA256_RE.fullmatch(evidence_sha) is None:
                raise ReferenceJobError(f"{digest_name} must be lowercase SHA-256")
    if (provider["trust_override_sha256"] is None) != (
        provider["human_approval_statement_sha256"] is None
    ):
        raise ReferenceJobError(
            "trust override and human approval statement must be supplied together"
        )
    if provider["human_approval_statement_sha256"] is not None and (
        not isinstance(provider["human_approval_statement_sha256"], str)
        or SHA256_RE.fullmatch(provider["human_approval_statement_sha256"]) is None
        or provider["human_approval_statement_sha256"] != APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256
    ):
        raise ReferenceJobError("human_approval_statement_sha256 must be lowercase SHA-256")
    gates = _closed(
        top["gates"],
        {
            "formula_authority_path",
            "formula_approval_path",
            "formula_approval_sha256",
            "memory_fit_evidence_path",
            "memory_fit_evidence_sha256",
            "cold_path_time_evidence_path",
            "cold_path_time_evidence_sha256",
            "memory_method_path",
            "memory_method_sha256",
            "cold_path_method_path",
            "cold_path_method_sha256",
            "architecture_metadata_path",
            "architecture_metadata_sha256",
            "image_build_identity_path",
            "image_build_identity_sha256",
            "bound_receipt_root",
        },
        "reference gates",
    )
    for path_name, digest_name in (
        ("memory_fit_evidence_path", "memory_fit_evidence_sha256"),
        ("cold_path_time_evidence_path", "cold_path_time_evidence_sha256"),
        ("memory_method_path", "memory_method_sha256"),
        ("cold_path_method_path", "cold_path_method_sha256"),
        ("architecture_metadata_path", "architecture_metadata_sha256"),
        ("image_build_identity_path", "image_build_identity_sha256"),
    ):
        evidence_path = gates[path_name]
        evidence_digest = gates[digest_name]
        if (evidence_path is None) != (evidence_digest is None):
            raise ReferenceJobError("reference gate path and SHA-256 must be supplied together")
        if evidence_path is not None:
            prefix = (
                "artifacts/local/"
                if path_name == "architecture_metadata_path"
                else "reports/local/"
            )
            gates[path_name] = _repo_path(root, evidence_path, path_name, prefix)
            if not isinstance(evidence_digest, str) or SHA256_RE.fullmatch(evidence_digest) is None:
                raise ReferenceJobError(f"{digest_name} must be lowercase SHA-256")
    receipt_root = gates["bound_receipt_root"]
    if receipt_root is not None:
        gates["bound_receipt_root"] = _repo_path(
            root, receipt_root, "bound_receipt_root", "reports/local/"
        )
    evidence_present = any(
        gates[name] is not None
        for name in (
            "memory_fit_evidence_path",
            "cold_path_time_evidence_path",
        )
    )
    reproducibility_fields = (
        "memory_method_path",
        "memory_method_sha256",
        "cold_path_method_path",
        "cold_path_method_sha256",
        "architecture_metadata_path",
        "architecture_metadata_sha256",
        "image_build_identity_path",
        "image_build_identity_sha256",
        "bound_receipt_root",
    )
    if evidence_present and any(gates[name] is None for name in reproducibility_fields):
        raise ReferenceJobError(
            "paid gate evidence requires complete schema-v2 reproducibility inputs"
        )
    formula_path = gates["formula_authority_path"]
    formula_sha = inputs["formula_authority_sha256"]
    if (formula_path is None) != (formula_sha is None):
        raise ReferenceJobError("formula authority path and SHA-256 must be supplied together")
    if formula_path is not None:
        gates["formula_authority_path"] = _repo_path(
            root,
            formula_path,
            "formula_authority_path",
            "reports/local/",
        )
    formula_approval_path = gates["formula_approval_path"]
    formula_approval_sha = gates["formula_approval_sha256"]
    if (formula_approval_path is None) != (formula_approval_sha is None):
        raise ReferenceJobError("formula approval path and SHA-256 must be supplied together")
    if formula_approval_path is not None:
        gates["formula_approval_path"] = _repo_path(
            root,
            formula_approval_path,
            "formula_approval_path",
            "reports/local/",
        )
        if (
            not isinstance(formula_approval_sha, str)
            or SHA256_RE.fullmatch(formula_approval_sha) is None
        ):
            raise ReferenceJobError("formula_approval_sha256 must be lowercase SHA-256")
    approval_path = top["approval_artifact_path"]
    if approval_path is not None:
        approval_path = _repo_path(root, approval_path, "approval_artifact_path", "configs/local/")
    canonical = json.dumps(top, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    challenge_material = {
        key: value for key, value in top.items() if key != "approval_artifact_path"
    }
    challenge_json = json.dumps(
        challenge_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return ReferenceJobConfig(
        experiment_id=top["experiment_id"],
        original_approved_plan_path=original_plan_path,
        original_approved_plan_sha256=original_plan_sha,
        approved_amendment_path=amendment_path,
        approved_amendment_sha256=amendment_sha,
        approved_trust_override_plan_path=trust_plan_path,
        approved_trust_override_plan_sha256=trust_plan_sha,
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
        expected_plan_sha256=config.original_approved_plan_sha256,
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
    formula_approval_verified = False
    formula_sha = config.inputs["formula_authority_sha256"]
    formula_path = config.gates["formula_authority_path"]
    if isinstance(formula_sha, str) and isinstance(formula_path, str):
        try:
            formula_result = verify_formula_authority(
                root / formula_path,
                expected_sha256=formula_sha,
                expected_maximum_context_tokens=int(config.inputs["evaluation_max_context_tokens"]),
                expected_timeout_seconds=int(config.resources["timeout_seconds"]),
            )
            formula_verified = bool(formula_result["verified"])
            formula_human_approved = bool(formula_result["human_approved"])
            approval_path = config.gates["formula_approval_path"]
            approval_sha = config.gates["formula_approval_sha256"]
            if isinstance(approval_path, str) and isinstance(approval_sha, str):
                formula_approval_verified = bool(
                    verify_formula_approval_receipt(
                        root / approval_path,
                        expected_sha256=approval_sha,
                        expected_formula_path=formula_path,
                        expected_formula_sha256=formula_sha,
                    )["verified"]
                )
        except ReferenceGateError:
            formula_verified = False
    if formula_sha is None:
        blockers.append("formula_authority_missing")
    elif not formula_verified:
        blockers.append("formula_authority_unverified")
    elif not formula_human_approved:
        blockers.append("formula_authority_review_pending")
    elif not formula_approval_verified:
        blockers.append("formula_approval_receipt_unverified")
    provider_concurrency_proven = False
    provider_constraint_authority = "unproven"
    trust_override_accepted = False
    provider_billing_scope_proven = False
    constraint_path = config.provider["constraint_contract_path"]
    constraint_sha = config.provider["constraint_contract_sha256"]
    observation_path = config.provider["observation_receipt_path"]
    observation_sha = config.provider["observation_receipt_sha256"]
    billing_path = config.provider["billing_authority_path"]
    billing_sha = config.provider["billing_authority_sha256"]
    constraint: dict[str, object] | None = None
    if all(
        isinstance(value, str)
        for value in (constraint_path, constraint_sha, observation_path, observation_sha)
    ):
        try:
            constraint = verify_provider_constraint_contract(
                root / str(constraint_path),
                expected_sha256=str(constraint_sha),
                expected_workspace_scope_sha256=str(config.provider["workspace_scope_sha256"]),
                expected_environment_scope_sha256=str(config.provider["environment_scope_sha256"]),
                expected_amendment_sha256=config.approved_amendment_sha256,
            )
            observation = verify_provider_observation_receipt(
                root / str(observation_path),
                expected_sha256=str(observation_sha),
                expected_contract_sha256=str(constraint_sha),
                expected_workspace_scope_sha256=str(config.provider["workspace_scope_sha256"]),
                expected_environment_scope_sha256=str(config.provider["environment_scope_sha256"]),
                expected_amendment_sha256=config.approved_amendment_sha256,
                validated_at=_now_datetime(),
                maximum_age_seconds=PROVIDER_APPROVAL_OBSERVATION_MAX_AGE_SECONDS,
            )
            provider_concurrency_proven = bool(constraint["proven"] and observation["proven"])
            provider_constraint_authority = "fresh_observation"
        except ReferenceGateError:
            trust_path = config.provider["trust_override_path"]
            trust_sha = config.provider["trust_override_sha256"]
            statement_sha = config.provider["human_approval_statement_sha256"]
            if isinstance(constraint, dict) and all(
                isinstance(value, str) for value in (trust_path, trust_sha, statement_sha)
            ):
                try:
                    observation = verify_provider_observation_receipt_for_trust_override(
                        root / str(observation_path),
                        expected_sha256=str(observation_sha),
                        expected_contract_sha256=str(constraint_sha),
                        expected_workspace_scope_sha256=str(
                            config.provider["workspace_scope_sha256"]
                        ),
                        expected_environment_scope_sha256=str(
                            config.provider["environment_scope_sha256"]
                        ),
                        expected_amendment_sha256=config.approved_amendment_sha256,
                        validated_at=_now_datetime(),
                    )
                    override = verify_provider_observation_trust_override(
                        root / str(trust_path),
                        expected_sha256=str(trust_sha),
                        expected_original_plan_sha256=config.original_approved_plan_sha256,
                        expected_provider_amendment_sha256=config.approved_amendment_sha256,
                        expected_trust_override_plan_sha256=(
                            config.approved_trust_override_plan_sha256
                        ),
                        expected_contract_sha256=str(constraint_sha),
                        expected_observation_receipt_sha256=str(observation_sha),
                        expected_screenshot_sha256=str(
                            config.provider["observation_screenshot_sha256"]
                        ),
                        expected_workspace_scope_sha256=str(
                            config.provider["workspace_scope_sha256"]
                        ),
                        expected_environment_scope_sha256=str(
                            config.provider["environment_scope_sha256"]
                        ),
                        expected_human_statement_sha256=(APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256),
                    )
                    provider_concurrency_proven = bool(
                        constraint["proven"]
                        and observation["proven"]
                        and observation["screenshot_sha256"]
                        == config.provider["observation_screenshot_sha256"]
                        and override["proven"]
                    )
                    trust_override_accepted = provider_concurrency_proven
                    if provider_concurrency_proven:
                        provider_constraint_authority = "human_trust_override"
                except ReferenceGateError:
                    provider_concurrency_proven = False
    if isinstance(billing_path, str) and isinstance(billing_sha, str):
        try:
            billing_authority = verify_provider_billing_authority(
                root / billing_path,
                expected_sha256=billing_sha,
                expected_environment_scope_sha256=str(config.provider["environment_scope_sha256"]),
            )
            provider_billing_scope_proven = bool(
                billing_authority["proven"]
                and billing_authority["authoritative_report_identity_sha256"]
                == config.provider["authoritative_report_identity_sha256"]
                and billing_authority["billing_completeness_delay_seconds"]
                == config.provider["billing_completeness_delay_seconds"]
            )
        except ReferenceGateError:
            provider_billing_scope_proven = False
    if not provider_concurrency_proven:
        blockers.append("provider_concurrency_unproven")
    if not provider_billing_scope_proven:
        blockers.append("provider_billing_scope_unproven")
    memory_fit_proven = False
    memory_path = config.gates["memory_fit_evidence_path"]
    memory_sha = config.gates["memory_fit_evidence_sha256"]
    verified_formula_sha = formula_sha if formula_verified else None
    memory_method_path = config.gates["memory_method_path"]
    memory_method_sha = config.gates["memory_method_sha256"]
    if (
        isinstance(memory_path, str)
        and isinstance(memory_sha, str)
        and isinstance(verified_formula_sha, str)
        and isinstance(memory_method_path, str)
        and isinstance(memory_method_sha, str)
    ):
        try:
            reproducible = verify_memory_evidence_reproducible(
                method_path=root / memory_method_path,
                method_sha256=memory_method_sha,
                evidence_path=root / memory_path,
                evidence_sha256=memory_sha,
                inventory_path=root / str(config.authority_files["weight_inventory_path"]),
                architecture_path=root / str(config.gates["architecture_metadata_path"]),
                expected_architecture_sha256=str(
                    config.gates["architecture_metadata_sha256"]
                ),
                runtime_receipt_path=root / str(config.authority_files["runtime_receipt_path"]),
                image_build_identity_path=root / str(config.gates["image_build_identity_path"]),
                evaluation_lock_path=root / str(config.authority_files["evaluation_lock_path"]),
                receipt_root=root / str(config.gates["bound_receipt_root"]),
            )
            memory_fit_proven = (
                verify_memory_fit_evidence(
                    root / memory_path,
                    expected_sha256=memory_sha,
                    expected_inventory_sha256=str(config.inputs["weight_inventory_sha256"]),
                    expected_tensor_bytes=int(config.inputs["weight_inventory_tensor_bytes"]),
                    expected_method_sha256=memory_method_sha,
                    expected_evaluation_lock_sha256=str(config.inputs["evaluation_lock_sha256"]),
                    expected_maximum_context_tokens=int(
                        config.inputs["evaluation_max_context_tokens"]
                    ),
                    expected_runtime_receipt_sha256=str(config.inputs["runtime_receipt_sha256"]),
                    expected_image_build_identity_sha256=str(
                        config.gates["image_build_identity_sha256"]
                    ),
                    require_schema_v2=True,
                ).proven
                and reproducible
            )
        except (ReferenceGateError, ReferenceEvidenceError):
            memory_fit_proven = False
    if not memory_fit_proven:
        blockers.append("memory_fit_unproven")
    time_budget_proven = False
    time_path = config.gates["cold_path_time_evidence_path"]
    time_sha = config.gates["cold_path_time_evidence_sha256"]
    time_method_path = config.gates["cold_path_method_path"]
    time_method_sha = config.gates["cold_path_method_sha256"]
    if (
        isinstance(time_path, str)
        and isinstance(time_sha, str)
        and isinstance(verified_formula_sha, str)
        and isinstance(time_method_path, str)
        and isinstance(time_method_sha, str)
    ):
        try:
            reproducible = verify_cold_path_evidence_reproducible(
                method_path=root / time_method_path,
                method_sha256=time_method_sha,
                evidence_path=root / time_path,
                evidence_sha256=time_sha,
                inventory_path=root / str(config.authority_files["weight_inventory_path"]),
                runtime_receipt_path=root / str(config.authority_files["runtime_receipt_path"]),
                image_build_identity_path=root / str(config.gates["image_build_identity_path"]),
                evaluation_lock_path=root / str(config.authority_files["evaluation_lock_path"]),
                receipt_root=root / str(config.gates["bound_receipt_root"]),
            )
            time_budget_proven = (
                verify_cold_path_time_evidence(
                    root / time_path,
                    expected_sha256=time_sha,
                    timeout_seconds=int(config.resources["timeout_seconds"]),
                    expected_method_sha256=time_method_sha,
                    expected_evaluation_lock_sha256=str(config.inputs["evaluation_lock_sha256"]),
                    expected_maximum_context_tokens=int(
                        config.inputs["evaluation_max_context_tokens"]
                    ),
                    expected_inventory_sha256=str(config.inputs["weight_inventory_sha256"]),
                    expected_runtime_receipt_sha256=str(config.inputs["runtime_receipt_sha256"]),
                    expected_image_build_identity_sha256=str(
                        config.gates["image_build_identity_sha256"]
                    ),
                    require_schema_v2=True,
                ).proven
                and reproducible
            )
        except (ReferenceGateError, ReferenceEvidenceError):
            time_budget_proven = False
    if not time_budget_proven:
        blockers.append("cold_path_time_budget_unproven")
    approval_valid = False
    residual_risk_accepted = trust_override_accepted
    if config.approval_artifact_path is not None:
        try:
            approval = validate_reference_approval(
                root / config.approval_artifact_path,
                expected_challenge_sha256=config.challenge_sha256,
                expected_original_plan_sha256=config.original_approved_plan_sha256,
                expected_amendment_sha256=config.approved_amendment_sha256,
                expected_trust_override_plan_sha256=(config.approved_trust_override_plan_sha256),
                expected_provider={
                    name: config.provider[name]
                    for name in (
                        "constraint_contract_sha256",
                        "observation_receipt_sha256",
                        "billing_authority_sha256",
                        "workspace_scope_sha256",
                        "environment_scope_sha256",
                        "authoritative_report_identity_sha256",
                        "billing_completeness_delay_seconds",
                        "trust_override_sha256",
                    )
                },
                now=_now_datetime(),
            )
            approval_valid = (
                approval["reviewed_commit_sha256"] == config.inputs["reviewed_commit_sha256"]
            )
            residual_risk_accepted = residual_risk_accepted or approval_valid
        except ReferenceJobError:
            approval_valid = False
    if not residual_risk_accepted:
        blockers.append("provider_residual_cost_risk_unaccepted")
    if not approval_valid:
        blockers.append("execution_approval_missing")
    return {
        "schema_version": 3,
        "kind": "modal_reference_preview",
        "submit": False,
        "scheduling_enabled": False,
        "cloud_upload": False,
        "weights_transferred": False,
        "actual_cost_usd": "0",
        "local_reservation_limit_usd": format(budget_preview.local_reservation_limit_usd, "f"),
        "estimated_cost_usd": format(budget_preview.estimated_cost_usd, "f"),
        "resources": config.resources,
        "challenge_sha256": config.challenge_sha256,
        "config_sha256": config.sha256,
        "reference_execution_scope_sha256": config.reference_execution_scope_sha256,
        "provider_constraint_authority": provider_constraint_authority,
        "blockers": blockers,
    }


def plan_reference_bootstrap_preview(
    config: ReferenceJobConfig,
    *,
    root: Path,
    request_path: Path,
    request_sha256: str,
    image_lock_path: Path,
    image_lock_sha256: str,
    provider_capability_path: Path,
    provider_capability_sha256: str,
    billing_authority_path: Path,
    billing_receipt_path: Path,
    billing_report_path: Path,
    publication_manifest_path: Path,
    authority_path: Path = AUTHORITY_PATH,
    bootstrap_authority_path: Path = BOOTSTRAP_AUTHORITY_PATH,
) -> dict[str, object]:
    """Evaluate every deterministic gate while leaving empirical facts pending."""
    root = root.resolve()
    base = plan_reference_preview(config, root=root)
    empirical_only = {
        "cold_path_time_budget_unproven",
        "execution_approval_missing",
        "memory_fit_unproven",
    }
    blockers = [item for item in base["blockers"] if item not in empirical_only]
    request = None
    image_lock = None
    try:
        request_bytes = (root / request_path).read_bytes()
        if hashlib.sha256(request_bytes).hexdigest() != request_sha256:
            raise ReferenceBootstrapError("bootstrap request SHA-256 mismatch")
        request = validate_bootstrap_request_bytes(request_bytes)
    except (OSError, ReferenceBootstrapError):
        blockers.append("bootstrap_request_unverified")
    try:
        image_bytes = (root / image_lock_path).read_bytes()
        if hashlib.sha256(image_bytes).hexdigest() != image_lock_sha256:
            raise ReferenceBootstrapError("image lock SHA-256 mismatch")
        image_lock = validate_image_lock_bytes(image_bytes)
        if request is not None:
            validate_request_image_lock(request, image_lock)
    except (OSError, ReferenceBootstrapError):
        blockers.append("image_lock_unverified")
    try:
        validate_reference_authority(root, authority_path)
        validate_reference_bootstrap_authority(root, bootstrap_authority_path)
    except ReferenceAuthorityError:
        blockers.append("bootstrap_authority_unverified")
    if not _verify_reference_authorities(config, root=root):
        blockers.append("authority_artifacts_unverified")
    if request is not None and image_lock is not None:
        raw_request = json.loads(request.canonical_json)
        capability = raw_request["provider_capability"]
        try:
            validate_provider_capability_receipt(
                root / provider_capability_path,
                expected_sha256=provider_capability_sha256,
                image_recipe_sha256=image_lock.recipe_sha256,
                billing_authority_path=root / billing_authority_path,
                billing_receipt_path=root / billing_receipt_path,
                billing_report_path=root / billing_report_path,
            )
            if capability["receipt_sha256"] != provider_capability_sha256:
                raise ProviderEvidenceError("provider capability request binding drift")
        except ProviderEvidenceError:
            blockers.append("provider_capability_unverified")
    else:
        blockers.append("provider_capability_unverified")
    try:
        manifest = load_manifest(root, publication_manifest_path)
        publication = scan_publication(
            root,
            public_remote=manifest.public_remote,
            protected_values=manifest.private_values,
        )
        if not publication["ok"]:
            blockers.append("publication_scan_failed")
    except PublicationError:
        blockers.append("publication_scan_failed")
    blockers = sorted(set(blockers))
    return {
        "schema_version": 1,
        "kind": "modal_reference_bootstrap_preview",
        "submit": False,
        "actual_cost_usd": "0",
        "weights_transferred": False,
        "bootstrap_ready": not blockers,
        "deterministic_state": "bootstrap_ready" if not blockers else "stopped",
        "empirical": {fact: "pending" for fact in EMPIRICAL_FACTS},
        "configured_context_tokens": 262144,
        "proven_useful_context_tokens": None,
        "request_sha256": request.sha256 if request is not None else None,
        "image_lock_sha256": image_lock.sha256 if image_lock is not None else None,
        "provider_capability_sha256": provider_capability_sha256,
        "blockers": blockers,
    }


def _verify_runtime_receipt_bytes(
    path: Path, *, root: Path, runtime_lock: RuntimeLock, expected_sha256: str
) -> bool:
    receipt_bytes = path.read_bytes()
    receipt = json.loads(receipt_bytes.decode("utf-8"))
    verify_current_installed_environment(receipt, root=root, lock=runtime_lock)
    return hashlib.sha256(receipt_bytes).hexdigest() == expected_sha256


def _load_bound_evaluation_lock(
    path: Path, *, expected_file_sha256: str
) -> dict[str, Any]:
    content = path.read_bytes()
    raw = json.loads(content.decode("utf-8"))
    if (
        not isinstance(raw, dict)
        or hashlib.sha256(content).hexdigest() != expected_file_sha256
    ):
        raise ReferenceJobError("evaluation lock bytes drift")
    return raw


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
            name: (item["size_bytes"], item["lfs_sha256"]) for name, item in source_metadata.items()
        }
        inventory_raw = json.loads(paths["weight_inventory_path"].read_text(encoding="utf-8"))
        runtime_lock = load_runtime_lock(paths["runtime_lock_path"], root=root)
        evaluation_raw = _load_bound_evaluation_lock(
            paths["evaluation_lock_path"],
            # The config key binds exact persisted bytes; semantic provenance below
            # binds the canonical identity returned by validation.
            expected_file_sha256=str(config.inputs["evaluation_lock_sha256"]),
        )
        fixture_root = paths["evaluation_fixture_root"]
        fixture_bytes = {
            fixture["fixture_id"]: (fixture_root / f"{fixture['fixture_id']}.json").read_bytes()
            for fixture in evaluation_raw["fixtures"]
        }
        evaluation_lock = validate_pending_evaluation_lock(
            evaluation_raw, fixture_bytes=fixture_bytes
        )
        evaluation_lock_canonical_sha256 = evaluation_lock.sha256
        expected_bindings = {
            "provenance_manifest_sha256": config.inputs["provenance_manifest_sha256"],
            "tokenizer_sha256": tokenizer_entry["local_content"]["sha256"],
            "runtime_lock_sha256": runtime_lock.sha256,
            "evaluation_lock_sha256": evaluation_lock_canonical_sha256,
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
            or inventory.source_revision != config.inputs["source_revision"]
        ):
            return False
        return _verify_runtime_receipt_bytes(
            paths["runtime_receipt_path"],
            root=root,
            runtime_lock=runtime_lock,
            expected_sha256=str(config.inputs["runtime_receipt_sha256"]),
        )
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
            lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]",
            redacted,
        )
    return redacted[:maximum_chars]


def validate_reference_approval(
    path: Path,
    *,
    expected_challenge_sha256: str,
    expected_original_plan_sha256: str,
    expected_amendment_sha256: str,
    expected_trust_override_plan_sha256: str,
    expected_provider: dict[str, object],
    now: datetime,
) -> dict[str, str]:
    if expected_original_plan_sha256 != ORIGINAL_APPROVED_PLAN_SHA256:
        raise ReferenceJobError("reference approval original plan authority is not accepted")
    if expected_amendment_sha256 != APPROVED_PROVIDER_AMENDMENT_SHA256:
        raise ReferenceJobError("reference approval amendment authority is not accepted")
    if expected_trust_override_plan_sha256 != APPROVED_TRUST_OVERRIDE_PLAN_SHA256:
        raise ReferenceJobError("reference approval trust override authority is not accepted")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceJobError(f"cannot read reference approval: {exc}") from exc
    fields = {
        "schema_version",
        "kind",
        "challenge_sha256",
        "reviewed_commit_sha256",
        "original_approved_plan_sha256",
        "approved_amendment_sha256",
        "approved_trust_override_plan_sha256",
        "constraint_contract_sha256",
        "observation_receipt_sha256",
        "billing_authority_sha256",
        "workspace_scope_sha256",
        "environment_scope_sha256",
        "authoritative_report_identity_sha256",
        "billing_completeness_delay_seconds",
        "trust_override_sha256",
        "provider_residual_cost_risk_accepted",
        "local_reservation_limit_usd",
        "expires_at",
    }
    approval = _closed(raw, fields, "reference approval")
    if approval["schema_version"] != 3 or approval["kind"] != "reference_execution_approval":
        raise ReferenceJobError("unsupported reference approval")
    if approval["challenge_sha256"] != expected_challenge_sha256:
        raise ReferenceJobError("reference approval challenge mismatch")
    if approval["original_approved_plan_sha256"] != expected_original_plan_sha256:
        raise ReferenceJobError("reference approval original plan mismatch")
    if approval["approved_amendment_sha256"] != expected_amendment_sha256:
        raise ReferenceJobError("reference approval amendment mismatch")
    if approval["approved_trust_override_plan_sha256"] != expected_trust_override_plan_sha256:
        raise ReferenceJobError("reference approval trust override plan mismatch")
    for field in (
        "constraint_contract_sha256",
        "observation_receipt_sha256",
        "billing_authority_sha256",
        "workspace_scope_sha256",
        "environment_scope_sha256",
        "authoritative_report_identity_sha256",
        "trust_override_sha256",
    ):
        if approval[field] != expected_provider.get(field):
            raise ReferenceJobError(f"reference approval {field} mismatch")
        if field == "trust_override_sha256" and approval[field] is None:
            continue
        if not isinstance(approval[field], str) or SHA256_RE.fullmatch(approval[field]) is None:
            raise ReferenceJobError(f"reference approval {field} is invalid")
    if approval["billing_completeness_delay_seconds"] != expected_provider.get(
        "billing_completeness_delay_seconds"
    ):
        raise ReferenceJobError("reference approval billing completeness delay mismatch")
    if approval["provider_residual_cost_risk_accepted"] is not True:
        raise ReferenceJobError("provider residual cost risk is not accepted")
    if IMMUTABLE_REVISION_RE.fullmatch(str(approval["reviewed_commit_sha256"])) is None:
        raise ReferenceJobError("reference approval commit is invalid")
    if approval["local_reservation_limit_usd"] != format(
        ReferenceBudgetGuard.LOCAL_RESERVATION_LIMIT, "f"
    ):
        raise ReferenceJobError("reference approval local reservation limit is invalid")
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


def plan_reference_dry_run(config_path: Path, db_path: Path, root: Path) -> dict[str, object]:
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
                plan_modal_dry_run(args.config, args.db, args.root.resolve(), dry_run=args.dry_run)
            )
    except Exception as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
