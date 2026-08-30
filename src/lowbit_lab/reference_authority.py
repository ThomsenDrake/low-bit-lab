"""Closed validation for the human-approved autonomous reference capability."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    REFERENCE_ADDITIONAL_BASE_COMMIT,
    REFERENCE_ADDITIONAL_CORRECTED_PREFLIGHT_REQUEST_SHA256,
    REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD,
    REFERENCE_ADDITIONAL_FORFEITED_REQUEST_SHA256,
    REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD,
    REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
    REFERENCE_ADDITIONAL_PRIOR_SPEND_USD,
    REFERENCE_ADDITIONAL_REPLACEMENT_AUTHORITY_SHA256,
    REFERENCE_ADDITIONAL_REPLACEMENT_BASE_COMMIT,
    REFERENCE_ADDITIONAL_REPLACEMENT_FORFEIT_RECEIPT_SHA256,
    REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_ARTIFACT_SHA256,
    REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_SHA256,
    REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
    REFERENCE_ADDITIONAL_STATEMENT_ARTIFACT_SHA256,
    REFERENCE_ADDITIONAL_STATEMENT_SHA256,
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_AUTHORITY_STATEMENT_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
    REFERENCE_BOOTSTRAP_STATEMENT_SHA256,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_RECOVERY_AUTHORITY_SHA256,
    REFERENCE_RECOVERY_STATEMENT_SHA256,
    REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
    REFERENCE_SIGNED_CDN_MERGE_COMMIT,
    REFERENCE_SIGNED_CDN_STATEMENT_SHA256,
    REFERENCE_SIGNED_REDIRECT_POLICY,
    REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256,
    REFERENCE_WORKSPACE_RECONCILIATION_BASE_COMMIT,
    REFERENCE_WORKSPACE_RECONCILIATION_STATEMENT_SHA256,
)
from lowbit_lab.handoff import canonical_json, sha256_json

ACTION_CLASSES = (
    "zero_spend_prepare",
    "u8_reference_once",
    "billing_reconcile",
    "u9_compile_proposal",
)

STATEMENT_PATH = Path("configs/local/reference-authority-statement.txt")
AUTHORITY_PATH = Path("configs/local/reference-campaign-authority.json")
BOOTSTRAP_STATEMENT_PATH = Path("configs/local/reference-bootstrap-statement.txt")
BOOTSTRAP_AUTHORITY_PATH = Path("configs/local/reference-bootstrap-authority.json")
SIGNED_CDN_STATEMENT_PATH = Path("configs/local/reference-signed-cdn-statement.txt")
SIGNED_CDN_AUTHORITY_PATH = Path("configs/local/reference-signed-cdn-authority.json")
RECOVERY_STATEMENT_PATH = Path("configs/local/reference-recovery-standing-authority.txt")
RECOVERY_AUTHORITY_PATH = Path("configs/local/reference-recovery-authority.json")
WORKSPACE_RECONCILIATION_STATEMENT_PATH = Path(
    "docs/plans/local/2026-08-27-workspace-scope-reconciliation-authority.txt"
)
WORKSPACE_RECONCILIATION_AUTHORITY_PATH = Path(
    "configs/local/reference-workspace-scope-reconciliation-authority.json"
)
ADDITIONAL_STATEMENT_PATH = Path("configs/local/reference-additional-u8-standing-authority.txt")
ADDITIONAL_AUTHORITY_PATH = Path("configs/local/reference-additional-u8-authority.json")
ADDITIONAL_SETTLEMENT_RECEIPT_PATH = Path(
    "reports/local/reference-replacement-settlement-receipt.json"
)
ADDITIONAL_REPLACEMENT_STATEMENT_PATH = Path(
    "configs/local/reference-additional-preprovider-replacement-statement.txt"
)
ADDITIONAL_REPLACEMENT_AUTHORITY_PATH = Path(
    "configs/local/reference-additional-preprovider-replacement-authority.json"
)
ADDITIONAL_REPLACEMENT_FORFEIT_RECEIPT_PATH = Path(
    "reports/local/reference-additional-preprovider-forfeit-receipt.json"
)
CONTROLLING_PLANS = {
    "original_reference_baseline": (
        Path("docs/plans/local/2026-08-21-2358-feat-full-weight-baseline-plan.md"),
        "a45e791c83466f545f6ac204857722478a080a1ea4a007c47510fbc4aa2b86c4",
    ),
    "provider_constraint_amendment": (
        Path("docs/plans/local/2026-08-22-1126-feat-provider-constraint-amendment-plan.md"),
        "0de9ff2c7ae791d524e59e6018b0356ea0d95ec9782754eaef411db8862ee114",
    ),
    "provider_trust_override": (
        Path("docs/plans/local/2026-08-23-provider-observation-trust-override-plan.md"),
        "277e2359b33f334e96aa60a4e146bb57a640c21b5e24d63d34d9f811c06b048e",
    ),
    "autonomous_reference_baseline": (
        Path("docs/plans/local/2026-08-25-1200-feat-autonomous-reference-baseline-plan.md"),
        "03b7e838d7530603086c6afdd62ec0ac5b778fa73945681badeff4ecac627a0c",
    ),
}

BOOTSTRAP_ACTION_CLASS = "u8_reference_once"
BOOTSTRAPPED_PROVIDER_FACTS = (
    "cold_path_timing",
    "provider_image_identity",
    "runtime_allocator_overhead",
    "usable_gpu_memory",
)
BOOTSTRAP_PRE_SUBMIT_GATES = (
    "clean_tree",
    "cumulative_budget",
    "evaluation_lock",
    "immutable_inventory",
    "known_memory_lower_bound",
    "privacy",
    "provenance",
    "resource_envelope",
    "source_hashes",
    "static_lineage",
)
ADDITIONAL_ACTION_CLASS = "u8_reference_additional_once"
ADDITIONAL_REQUIRED_PRE_SUBMIT_GATES = (
    "lineage",
    "clean_tree",
    "privacy",
    "provenance",
    "evaluation_lock",
    "runtime",
    "memory_lower_bound",
    "provider_environment",
    "resource_envelope",
    "watchdog",
    "budget",
)


class ReferenceAuthorityError(ValueError):
    pass


def _expected_authority() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "autonomous_reference_baseline_authority",
        "statement_sha256": REFERENCE_AUTHORITY_STATEMENT_SHA256,
        "controlling_plans": {name: digest for name, (_, digest) in CONTROLLING_PLANS.items()},
        "action_classes": list(ACTION_CLASSES),
        "u8_slots": 1,
        "incremental_u8_cap_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
        "cumulative_lab_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
        "gpu": "A100-80GB:1",
        "max_concurrent_containers": 1,
        "timeout_seconds": 2700,
        "ephemeral_disk_mib": 524288,
        "provider_retries": 0,
        "application_retries": 0,
        "configured_context_tokens": 262144,
        "weights_remote_public_retrieval_authorized": True,
        "user_payloads_authorized": False,
        "secrets_authorized": False,
        "persistent_storage_authorized": False,
        "scheduling_authorized": False,
        "destructive_cleanup_authorized": False,
    }


def _expected_bootstrap_authority() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "reference_bootstrap_evidence_amendment",
        "statement_sha256": REFERENCE_BOOTSTRAP_STATEMENT_SHA256,
        "parent_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        "merge_commit": REFERENCE_BOOTSTRAP_MERGE_COMMIT,
        "action_class": BOOTSTRAP_ACTION_CLASS,
        "u8_slots": 1,
        "incremental_u8_cap_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
        "cumulative_lab_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
        "gpu": "A100-80GB:1",
        "max_concurrent_containers": 1,
        "timeout_seconds": 2700,
        "ephemeral_disk_mib": 524288,
        "provider_retries": 0,
        "application_retries": 0,
        "configured_context_tokens": 262144,
        "empirical_provider_facts_may_be_bootstrapped": list(BOOTSTRAPPED_PROVIDER_FACTS),
        "required_pre_submit_gates": list(BOOTSTRAP_PRE_SUBMIT_GATES),
        "staged_fail_closed_checkpoints_required": True,
        "immutable_public_file_hash_verification_required": True,
        "projected_timeout_stop_required": True,
        "sanitized_evidence_only": True,
        "context_reduction_authorized": False,
        "additional_provider_actions_authorized": False,
        "overlapping_reservations_authorized": False,
        "retries_or_fallback_authorized": False,
        "weights_remote_public_retrieval_authorized": True,
        "audited_function_definition_only": True,
        "secrets_mounts_volumes_schedules_authorized": False,
        "private_data_or_local_weight_transfer_authorized": False,
        "candidate_conversion_training_promotion_authorized": False,
        "submitted_failed_or_ambiguous_consumes_slot": True,
        "authoritative_billing_settlement_required": True,
        "u9_proposal_only": True,
    }


def _expected_signed_cdn_authority() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "reference_signed_cdn_transport_amendment",
        "statement_sha256": REFERENCE_SIGNED_CDN_STATEMENT_SHA256,
        "parent_bootstrap_authority_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        "parent_merge_commit": REFERENCE_SIGNED_CDN_MERGE_COMMIT,
        "action_class": BOOTSTRAP_ACTION_CLASS,
        "signed_redirect_policy": [
            {"host": host, "path_prefix": path_prefix}
            for host, path_prefix in REFERENCE_SIGNED_REDIRECT_POLICY
        ],
        "max_redirects": 5,
        "query_free_origins_required": True,
        "transient_query_only": True,
        "no_query_logging_persistence_return_or_reuse": True,
        "caller_headers_or_credentials_authorized": False,
        "retries_authorized": False,
        "additional_provider_actions_authorized": False,
    }


def build_reference_recovery_authority() -> dict[str, Any]:
    """Return the closed target-neutral recovery capability authorized by the human grant."""
    return {
        "schema_version": 1,
        "kind": "reference_preidentity_recovery_authority",
        "statement_sha256": REFERENCE_RECOVERY_STATEMENT_SHA256,
        "parent_signed_cdn_authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        "action_classes": [
            "zero_spend_phase1",
            "preidentity_zero_settlement",
            "u8_reference_replacement_once",
        ],
        "settlement_mode": "workspace_zero_preidentity",
        "failure_code": "auth_before_provider_identity",
        "provider": "modal",
        "original_u8_slot_remains_consumed": True,
        "replacement_u8_slots": 1,
        "replacement_retry_slots": 0,
        "incremental_u8_cap_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
        "cumulative_lab_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
        "settlement_actual_cost_usd": "0",
        "currency": "USD",
        "gpu": "A100-80GB:1",
        "max_concurrent_containers": 1,
        "timeout_seconds": 2700,
        "provider_retries": 0,
        "application_retries": 0,
        "configured_context_tokens": 262144,
        "proven_useful_context_tokens": None,
        "exact_workspace_zero_evidence_required": True,
        "provider_identity_must_be_absent": True,
        "authoritative_billing_settlement_required": True,
        "weights_remote_public_retrieval_authorized": True,
        "local_weight_transfer_authorized": False,
        "private_data_authorized": False,
        "user_payloads_authorized": False,
        "secrets_mounts_volumes_schedules_authorized": False,
        "destructive_cleanup_authorized": False,
        "candidate_conversion_training_promotion_authorized": False,
        "u9_proposal_only": True,
    }


def build_workspace_scope_reconciliation_authority(
    *,
    original_workspace_scope_sha256: str,
    authenticated_workspace_identity_sha256: str,
    original_reservation_id: str,
    original_execution_scope_sha256: str,
    billing_authority_sha256: str,
) -> dict[str, Any]:
    """Build the only approved historical-scope to authenticated-identity mapping."""
    return {
        "approved_base_commit": REFERENCE_WORKSPACE_RECONCILIATION_BASE_COMMIT,
        "authenticated_workspace_identity_sha256": authenticated_workspace_identity_sha256,
        "billing_authority_sha256": billing_authority_sha256,
        "digest_equality_asserted": False,
        "historical_config_rewrite": False,
        "kind": "reference_modal_workspace_scope_reconciliation_authority",
        "maximum_mapping_uses": 1,
        "original_execution_scope_sha256": original_execution_scope_sha256,
        "original_reservation_id": original_reservation_id,
        "original_workspace_scope_sha256": original_workspace_scope_sha256,
        "provider": "modal",
        "replacement_action": "u8_reference_replacement_once",
        "schema_version": 1,
        "statement_sha256": REFERENCE_WORKSPACE_RECONCILIATION_STATEMENT_SHA256,
    }


def build_reference_additional_authority() -> dict[str, Any]:
    """Return the closed third-generation U8 authority without reopening history."""
    return {
        "schema_version": 1,
        "kind": "reference_additional_u8_authority",
        "statement_sha256": REFERENCE_ADDITIONAL_STATEMENT_SHA256,
        "statement_artifact_sha256": REFERENCE_ADDITIONAL_STATEMENT_ARTIFACT_SHA256,
        "statement_framing": "utf-8-lf-paragraphs-terminal-lf",
        "approved_base_commit": REFERENCE_ADDITIONAL_BASE_COMMIT,
        "parent_recovery_authority_sha256": REFERENCE_RECOVERY_AUTHORITY_SHA256,
        "parent_signed_cdn_authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        "settled_replacement_receipt_sha256": (REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256),
        "settled_replacement_execution_scope_sha256": (
            REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256
        ),
        "action_class": ADDITIONAL_ACTION_CLASS,
        "required_pre_submit_gates": list(ADDITIONAL_REQUIRED_PRE_SUBMIT_GATES),
        "additional_u8_slots": 1,
        "subsequent_retry_or_replacement_slots": 0,
        "authoritative_prior_spend_usd": str(REFERENCE_ADDITIONAL_PRIOR_SPEND_USD),
        "incremental_u8_cap_usd": str(REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD),
        "cumulative_lab_cap_usd": str(REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD),
        "currency": "USD",
        "gpu": "A100-80GB:1",
        "max_concurrent_containers": 1,
        "max_spawns": 1,
        "timeout_seconds": 2700,
        "provider_retries": 0,
        "application_retries": 0,
        "fallback_gpu_authorized": False,
        "configured_context_tokens": 262144,
        "proven_useful_context_tokens": None,
        "revision_pinned_remote_public_artifact_retrieval_authorized": True,
        "signed_cdn_size_sha256_privacy_provenance_timeout_controls_required": True,
        "sanitized_evaluation_evidence_only": True,
        "authenticated_local_provider_profile_only": True,
        "credential_values_may_be_read_copied_logged_persisted_or_passed": False,
        "provider_auth_receipt_required_before_submission_and_billing_capture": True,
        "private_data_authorized": False,
        "user_or_work_payloads_authorized": False,
        "local_weight_transfer_authorized": False,
        "secrets_passed_to_worker_authorized": False,
        "mounts_volumes_persistent_storage_authorized": False,
        "source_mounts_or_uploads_authorized": False,
        "scheduling_authorized": False,
        "destructive_cleanup_authorized": False,
        "overlapping_reservations_authorized": False,
        "additional_provider_actions_authorized": False,
        "candidate_conversion_training_promotion_authorized": False,
        "candidate_execution_authorized": False,
        "numeric_threshold_approval_authorized": False,
        "submitted_failed_timed_out_or_ambiguous_consumes_slot": True,
        "authoritative_billing_settlement_required": True,
        "tracked_repository_target_neutral_required": True,
        "target_specific_information_ignored_local_only": True,
        "promotion_privacy_lineage_budget_controls_may_be_weakened": False,
        "u9_after_successful_terminal_settlement_authorized": True,
        "u9_proposal_only": True,
    }


def build_reference_additional_replacement_authority() -> dict[str, Any]:
    """Return the closed amendment for one pre-provider-failure replacement."""
    return {
        "schema_version": 1,
        "kind": "reference_additional_preprovider_replacement_authority",
        "statement_sha256": REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_SHA256,
        "statement_artifact_sha256": (
            REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_ARTIFACT_SHA256
        ),
        "approved_base_commit": REFERENCE_ADDITIONAL_REPLACEMENT_BASE_COMMIT,
        "parent_additional_authority_sha256": REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
        "failed_request_sha256": REFERENCE_ADDITIONAL_FORFEITED_REQUEST_SHA256,
        "corrected_preflight_request_sha256": (
            REFERENCE_ADDITIONAL_CORRECTED_PREFLIGHT_REQUEST_SHA256
        ),
        "corrected_preflight_is_parent_evidence": True,
        "paid_child_regenerated_after_merge": True,
        "paid_child_irreversible_bindings": [
            "execution_scope_sha256",
            "request_sha256",
            "wsl_parity_receipt_sha256",
        ],
        "failed_command_disposition": "consumed_preprovider_forfeit",
        "failed_incremental_spend_usd": "0",
        "failed_reservation_created": False,
        "failed_provider_submitted": False,
        "failed_weight_transfer": False,
        "replacement_slots": 1,
        "subsequent_retry_or_replacement_slots": 0,
        "claim_is_irreversible": True,
        "incremental_u8_cap_usd": str(REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD),
        "cumulative_lab_cap_usd": str(REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD),
        "authoritative_prior_spend_usd": str(REFERENCE_ADDITIONAL_PRIOR_SPEND_USD),
        "currency": "USD",
        "gpu": "A100-80GB:1",
        "max_concurrent_containers": 1,
        "max_spawns": 1,
        "timeout_seconds": 2700,
        "provider_retries": 0,
        "application_retries": 0,
        "fallback_gpu_authorized": False,
        "configured_context_tokens": 262144,
        "proven_useful_context_tokens": None,
        "all_parent_privacy_provenance_transport_controls_unchanged": True,
        "private_data_or_local_weight_transfer_authorized": False,
        "mounts_volumes_storage_scheduling_authorized": False,
        "candidate_conversion_training_promotion_authorized": False,
        "u9_proposal_only": True,
    }


def build_reference_additional_forfeit_receipt() -> dict[str, Any]:
    """Return the deterministic receipt for the failure before mutable boundaries."""
    return {
        "schema_version": 1,
        "kind": "reference_additional_preprovider_forfeit_receipt",
        "amendment_authority_sha256": REFERENCE_ADDITIONAL_REPLACEMENT_AUTHORITY_SHA256,
        "parent_additional_authority_sha256": REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
        "failed_request_sha256": REFERENCE_ADDITIONAL_FORFEITED_REQUEST_SHA256,
        "corrected_request_sha256": (
            REFERENCE_ADDITIONAL_CORRECTED_PREFLIGHT_REQUEST_SHA256
        ),
        "disposition": "consumed_preprovider_forfeit",
        "incremental_spend_usd": "0",
        "reservation_created": False,
        "provider_contacted": False,
        "modal_submitted": False,
        "weight_transfer": False,
    }


def _read(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ReferenceAuthorityError(f"cannot read {label}") from exc


def _confined_path(root: Path, relative_path: Path, label: str) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ReferenceAuthorityError(f"{label} path is not repository-relative")
    resolved = (root / relative_path).resolve()
    if not resolved.is_relative_to(root):
        raise ReferenceAuthorityError(f"{label} resolves outside repository")
    return resolved


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReferenceAuthorityError("reference authority contains duplicate keys")
        value[key] = item
    return value


def validate_reference_authority(root: Path, authority_path: Path = AUTHORITY_PATH) -> str:
    """Validate exact statement, plan bytes, and the closed semantic authority."""
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise ReferenceAuthorityError("reference authority repository root is unavailable") from exc
    expected_authority = _confined_path(root, AUTHORITY_PATH, "reference authority")
    resolved_authority = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_authority != expected_authority:
        raise ReferenceAuthorityError("reference authority path is fixed")

    statement = _read(
        _confined_path(root, STATEMENT_PATH, "reference authority statement"),
        "reference authority statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or statement.endswith((b"\r", b"\n"))
        or hashlib.sha256(statement).hexdigest() != REFERENCE_AUTHORITY_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("reference authority statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("reference authority statement is not UTF-8") from exc

    for _, (relative_path, expected_digest) in CONTROLLING_PLANS.items():
        actual_digest = hashlib.sha256(
            _read(_confined_path(root, relative_path, "controlling plan"), "controlling plan")
        ).hexdigest()
        if actual_digest != expected_digest:
            raise ReferenceAuthorityError(
                f"controlling plan has drifted: {relative_path.as_posix()}"
            )

    authority_bytes = _read(resolved_authority, "reference authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("reference authority is not valid UTF-8 JSON") from exc
    expected = _expected_authority()
    canonical_bytes = (canonical_json(expected) + "\n").encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError("reference authority raw bytes are not canonical")
    if authority != expected or sha256_json(authority) != REFERENCE_AUTHORITY_SHA256:
        raise ReferenceAuthorityError("reference authority boundary has drifted")
    return REFERENCE_AUTHORITY_SHA256


def authorize_reference_action(
    root: Path,
    authority_path: Path,
    action_class: str,
) -> str:
    """Authorize only a named closed action; U8 replay is enforced by SQLite."""
    if action_class not in ACTION_CLASSES:
        raise ReferenceAuthorityError("reference action class is not authorized")
    authority_sha256 = validate_reference_authority(root, authority_path)
    return sha256_json({"authority_sha256": authority_sha256, "action_class": action_class})


def validate_reference_bootstrap_authority(
    root: Path,
    authority_path: Path = BOOTSTRAP_AUTHORITY_PATH,
) -> str:
    """Validate the amendment without replacing or broadening its parent."""
    validate_reference_authority(root, AUTHORITY_PATH)
    root = root.resolve(strict=True)
    expected_path = _confined_path(root, BOOTSTRAP_AUTHORITY_PATH, "reference bootstrap authority")
    resolved_path = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_path != expected_path:
        raise ReferenceAuthorityError("reference bootstrap authority path is fixed")

    statement = _read(
        _confined_path(root, BOOTSTRAP_STATEMENT_PATH, "reference bootstrap authority statement"),
        "reference bootstrap authority statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or statement.endswith((b"\r", b"\n"))
        or hashlib.sha256(statement).hexdigest() != REFERENCE_BOOTSTRAP_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("reference bootstrap authority statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError(
            "reference bootstrap authority statement is not UTF-8"
        ) from exc

    authority_bytes = _read(resolved_path, "reference bootstrap authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError(
            "reference bootstrap authority is not valid UTF-8 JSON"
        ) from exc
    expected = _expected_bootstrap_authority()
    canonical_bytes = (
        json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError("reference bootstrap authority raw bytes are not canonical")
    if authority != expected or sha256_json(authority) != REFERENCE_BOOTSTRAP_AUTHORITY_SHA256:
        raise ReferenceAuthorityError("reference bootstrap authority boundary has drifted")
    return REFERENCE_BOOTSTRAP_AUTHORITY_SHA256


def authorize_reference_bootstrap_action(
    root: Path,
    authority_path: Path,
    action_class: str,
) -> str:
    """Authorize only the already-granted one-shot U8 action."""
    if action_class != BOOTSTRAP_ACTION_CLASS:
        raise ReferenceAuthorityError("reference bootstrap action class is not authorized")
    authority_sha256 = validate_reference_bootstrap_authority(root, authority_path)
    return sha256_json({"authority_sha256": authority_sha256, "action_class": action_class})


def validate_reference_signed_cdn_authority(
    root: Path,
    authority_path: Path = SIGNED_CDN_AUTHORITY_PATH,
) -> str:
    """Validate the signed-CDN amendment without broadening its parent."""
    validate_reference_bootstrap_authority(root, BOOTSTRAP_AUTHORITY_PATH)
    root = root.resolve(strict=True)
    expected_path = _confined_path(root, SIGNED_CDN_AUTHORITY_PATH, "signed CDN authority")
    resolved_path = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_path != expected_path:
        raise ReferenceAuthorityError("signed CDN authority path is fixed")

    statement = _read(
        _confined_path(root, SIGNED_CDN_STATEMENT_PATH, "signed CDN authority statement"),
        "signed CDN authority statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or hashlib.sha256(statement).hexdigest() != REFERENCE_SIGNED_CDN_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("signed CDN authority statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("signed CDN authority statement is not UTF-8") from exc

    authority_bytes = _read(resolved_path, "signed CDN authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("signed CDN authority is not valid UTF-8 JSON") from exc
    expected = _expected_signed_cdn_authority()
    canonical_bytes = (
        json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError("signed CDN authority raw bytes are not canonical")
    if authority != expected or sha256_json(authority) != REFERENCE_SIGNED_CDN_AUTHORITY_SHA256:
        raise ReferenceAuthorityError("signed CDN authority boundary has drifted")
    return REFERENCE_SIGNED_CDN_AUTHORITY_SHA256


def validate_reference_recovery_authority(
    root: Path,
    authority_path: Path = RECOVERY_AUTHORITY_PATH,
) -> str:
    """Validate the pre-identity settlement grant without broadening its parent."""
    validate_reference_signed_cdn_authority(root, SIGNED_CDN_AUTHORITY_PATH)
    root = root.resolve(strict=True)
    expected_path = _confined_path(root, RECOVERY_AUTHORITY_PATH, "recovery authority")
    resolved_path = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_path != expected_path:
        raise ReferenceAuthorityError("recovery authority path is fixed")

    statement = _read(
        _confined_path(root, RECOVERY_STATEMENT_PATH, "recovery authority statement"),
        "recovery authority statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or hashlib.sha256(statement).hexdigest() != REFERENCE_RECOVERY_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("recovery authority statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("recovery authority statement is not UTF-8") from exc

    authority_bytes = _read(resolved_path, "recovery authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("recovery authority is not valid UTF-8 JSON") from exc
    expected = build_reference_recovery_authority()
    canonical_bytes = (canonical_json(expected) + "\n").encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError("recovery authority raw bytes are not canonical")
    if authority != expected or sha256_json(authority) != REFERENCE_RECOVERY_AUTHORITY_SHA256:
        raise ReferenceAuthorityError("recovery authority boundary has drifted")
    return REFERENCE_RECOVERY_AUTHORITY_SHA256


def validate_workspace_scope_reconciliation_authority(
    root: Path,
    authority_path: Path = WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
) -> dict[str, Any]:
    """Validate the exact one-time scope mapping without changing historical lineage."""
    validate_reference_recovery_authority(root, RECOVERY_AUTHORITY_PATH)
    root = root.resolve(strict=True)
    expected_path = _confined_path(
        root,
        WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
        "workspace reconciliation authority",
    )
    resolved_path = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_path != expected_path:
        raise ReferenceAuthorityError("workspace reconciliation authority path is fixed")

    statement = _read(
        _confined_path(
            root,
            WORKSPACE_RECONCILIATION_STATEMENT_PATH,
            "workspace reconciliation statement",
        ),
        "workspace reconciliation statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or hashlib.sha256(statement).hexdigest()
        != REFERENCE_WORKSPACE_RECONCILIATION_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("workspace reconciliation statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("workspace reconciliation statement is not UTF-8") from exc

    authority_bytes = _read(resolved_path, "workspace reconciliation authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        expected = build_workspace_scope_reconciliation_authority(
            original_workspace_scope_sha256=authority["original_workspace_scope_sha256"],
            authenticated_workspace_identity_sha256=authority[
                "authenticated_workspace_identity_sha256"
            ],
            original_reservation_id=authority["original_reservation_id"],
            original_execution_scope_sha256=authority["original_execution_scope_sha256"],
            billing_authority_sha256=authority["billing_authority_sha256"],
        )
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReferenceAuthorityError("workspace reconciliation authority is invalid") from exc
    digests = (
        expected["original_workspace_scope_sha256"],
        expected["authenticated_workspace_identity_sha256"],
        expected["original_execution_scope_sha256"],
        expected["billing_authority_sha256"],
    )
    if any(
        not isinstance(value, str)
        or SHA256_RE.fullmatch(value) is None
        for value in digests
    ):
        raise ReferenceAuthorityError("workspace reconciliation digest is invalid")
    if (
        expected["original_workspace_scope_sha256"]
        == expected["authenticated_workspace_identity_sha256"]
    ):
        raise ReferenceAuthorityError("workspace reconciliation must preserve distinct identities")
    canonical_bytes = (canonical_json(expected) + "\n").encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError(
            "workspace reconciliation authority raw bytes are not canonical"
        )
    if authority != expected or sha256_json(authority) != (
        REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
    ):
        raise ReferenceAuthorityError("workspace reconciliation authority boundary has drifted")
    return authority


def validate_reference_additional_authority(
    root: Path,
    authority_path: Path = ADDITIONAL_AUTHORITY_PATH,
) -> str:
    """Validate the exact append-only authority and its settled parent receipt."""
    validate_reference_recovery_authority(root, RECOVERY_AUTHORITY_PATH)
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise ReferenceAuthorityError(
            "additional authority repository root is unavailable"
        ) from exc

    expected_path = _confined_path(root, ADDITIONAL_AUTHORITY_PATH, "additional authority")
    resolved_path = (
        authority_path.resolve()
        if authority_path.is_absolute()
        else (root / authority_path).resolve()
    )
    if resolved_path != expected_path:
        raise ReferenceAuthorityError("additional authority path is fixed")

    statement = _read(
        _confined_path(root, ADDITIONAL_STATEMENT_PATH, "additional authority statement"),
        "additional authority statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or not statement.endswith(b"\n")
        or statement.endswith(b"\n\n")
        or b"\r" in statement
        or hashlib.sha256(statement).hexdigest() != REFERENCE_ADDITIONAL_STATEMENT_ARTIFACT_SHA256
        or hashlib.sha256(statement[:-1]).hexdigest() != REFERENCE_ADDITIONAL_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("additional authority statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("additional authority statement is not UTF-8") from exc

    receipt_bytes = _read(
        _confined_path(
            root,
            ADDITIONAL_SETTLEMENT_RECEIPT_PATH,
            "settled replacement receipt",
        ),
        "settled replacement receipt",
    )
    if hashlib.sha256(receipt_bytes).hexdigest() != (
        REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256
    ):
        raise ReferenceAuthorityError("settled replacement receipt bytes have drifted")
    try:
        receipt = json.loads(
            receipt_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("settled replacement receipt is invalid") from exc
    if receipt.get("execution_scope_sha256") != (REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256):
        raise ReferenceAuthorityError("settled replacement receipt execution scope has drifted")

    authority_bytes = _read(resolved_path, "additional authority")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("additional authority is not valid UTF-8 JSON") from exc
    expected = build_reference_additional_authority()
    canonical_bytes = (canonical_json(expected) + "\n").encode("utf-8")
    if authority_bytes != canonical_bytes:
        raise ReferenceAuthorityError("additional authority raw bytes are not canonical")
    if authority != expected or sha256_json(authority) != (REFERENCE_ADDITIONAL_AUTHORITY_SHA256):
        raise ReferenceAuthorityError("additional authority boundary has drifted")
    return REFERENCE_ADDITIONAL_AUTHORITY_SHA256


def validate_reference_additional_replacement_authority(root: Path) -> str:
    """Validate the exact amendment, deterministic forfeit, and unchanged parent."""
    validate_reference_additional_authority(root, ADDITIONAL_AUTHORITY_PATH)
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise ReferenceAuthorityError("additional replacement root is unavailable") from exc

    statement = _read(
        _confined_path(
            root,
            ADDITIONAL_REPLACEMENT_STATEMENT_PATH,
            "additional replacement statement",
        ),
        "additional replacement statement",
    )
    if (
        statement.startswith(b"\xef\xbb\xbf")
        or not statement.endswith(b"\n")
        or statement.endswith(b"\n\n")
        or b"\r" in statement
        or hashlib.sha256(statement).hexdigest()
        != REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_ARTIFACT_SHA256
        or hashlib.sha256(statement[:-1]).hexdigest()
        != REFERENCE_ADDITIONAL_REPLACEMENT_STATEMENT_SHA256
    ):
        raise ReferenceAuthorityError("additional replacement statement bytes have drifted")
    try:
        statement.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReferenceAuthorityError("additional replacement statement is not UTF-8") from exc

    authority_bytes = _read(
        _confined_path(
            root,
            ADDITIONAL_REPLACEMENT_AUTHORITY_PATH,
            "additional replacement authority",
        ),
        "additional replacement authority",
    )
    receipt_bytes = _read(
        _confined_path(
            root,
            ADDITIONAL_REPLACEMENT_FORFEIT_RECEIPT_PATH,
            "additional pre-provider forfeit receipt",
        ),
        "additional pre-provider forfeit receipt",
    )
    expected_authority = build_reference_additional_replacement_authority()
    expected_receipt = build_reference_additional_forfeit_receipt()
    if authority_bytes != (canonical_json(expected_authority) + "\n").encode("utf-8"):
        raise ReferenceAuthorityError("additional replacement authority bytes have drifted")
    if receipt_bytes != (canonical_json(expected_receipt) + "\n").encode("utf-8"):
        raise ReferenceAuthorityError("additional forfeit receipt bytes have drifted")
    try:
        authority = json.loads(
            authority_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        receipt = json.loads(
            receipt_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceAuthorityError("additional replacement artifacts are invalid") from exc
    if (
        authority != expected_authority
        or sha256_json(authority) != REFERENCE_ADDITIONAL_REPLACEMENT_AUTHORITY_SHA256
        or receipt != expected_receipt
        or sha256_json(receipt)
        != REFERENCE_ADDITIONAL_REPLACEMENT_FORFEIT_RECEIPT_SHA256
    ):
        raise ReferenceAuthorityError("additional replacement authority boundary has drifted")
    return REFERENCE_ADDITIONAL_REPLACEMENT_AUTHORITY_SHA256


def authorize_reference_additional_action(
    root: Path,
    authority_path: Path,
    action_class: str,
) -> str:
    """Authorize only the separately identified final U8 action class."""
    if action_class != ADDITIONAL_ACTION_CLASS:
        raise ReferenceAuthorityError("additional action class is not authorized")
    authority_sha256 = validate_reference_additional_authority(root, authority_path)
    return sha256_json({"authority_sha256": authority_sha256, "action_class": action_class})
