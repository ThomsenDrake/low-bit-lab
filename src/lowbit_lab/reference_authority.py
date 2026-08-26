"""Closed validation for the human-approved autonomous reference capability."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_AUTHORITY_STATEMENT_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
    REFERENCE_BOOTSTRAP_STATEMENT_SHA256,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
    REFERENCE_SIGNED_CDN_MERGE_COMMIT,
    REFERENCE_SIGNED_CDN_STATEMENT_SHA256,
    REFERENCE_SIGNED_REDIRECT_POLICY,
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
