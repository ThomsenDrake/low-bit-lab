"""Closed validation for the human-approved autonomous reference capability."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_AUTHORITY_STATEMENT_SHA256,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_INCREMENTAL_CAP_USD,
)
from lowbit_lab.handoff import sha256_json

ACTION_CLASSES = (
    "zero_spend_prepare",
    "u8_reference_once",
    "billing_reconcile",
    "u9_compile_proposal",
)

STATEMENT_PATH = Path("configs/local/reference-authority-statement.txt")
AUTHORITY_PATH = Path("configs/local/reference-campaign-authority.json")
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


class ReferenceAuthorityError(ValueError):
    pass


def _expected_authority() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "autonomous_reference_baseline_authority",
        "statement_sha256": REFERENCE_AUTHORITY_STATEMENT_SHA256,
        "controlling_plans": {
            name: digest for name, (_, digest) in CONTROLLING_PLANS.items()
        },
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
    canonical_bytes = (
        json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
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
    return sha256_json(
        {"authority_sha256": authority_sha256, "action_class": action_class}
    )
