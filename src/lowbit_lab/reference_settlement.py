"""Pure contracts for the one narrow pre-identity workspace-zero settlement mode.

This module performs no file, database, credential, or provider operations. It
validates byte snapshots supplied by the orchestration layer and returns only
closed, target-neutral lineage needed by the transactional database consumer.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from lowbit_lab.config import SHA256_RE

RECEIPT_KIND = "reference_workspace_zero_billing_evidence"
FAILURE_CODE = "auth_before_provider_identity"
# Modal's Click-based Linux CLI emits one LF after its JSON value. Recovery is
# WSL-only, so bind the exact authoritative stdout bytes instead of normalizing.
CANONICAL_EMPTY_REPORT = b"[]\n"
AUTH_METHOD_SHA256 = hashlib.sha256(
    b"modal-profile-current-before-and-after-with-reconciled-identity-binding/v2"
).hexdigest()
AUTH_RECEIPT_MAXIMUM_AGE_SECONDS = 300
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_RECEIPT_FIELDS = {
    "schema_version",
    "kind",
    "provider",
    "recovery_authority_sha256",
    "original_workspace_scope_sha256",
    "authenticated_workspace_identity_sha256",
    "workspace_reconciliation_authority_sha256",
    "auth_binding_sha256",
    "pre_auth_receipt_sha256",
    "post_auth_receipt_sha256",
    "billing_authority_sha256",
    "billing_method_sha256",
    "authoritative_report_identity_sha256",
    "reservation_id",
    "original_execution_scope_sha256",
    "failure_code",
    "query_start",
    "query_end",
    "acquired_at",
    "completeness_delay_seconds",
    "actual_cost_usd",
    "currency",
    "report_sha256",
    "report_size_bytes",
    "row_count",
    "pagination_complete",
    "filters",
    "all_environments",
    "all_resources",
}
_AUTH_RECEIPT_FIELDS = {
    "authenticated_at",
    "binding_sha256",
    "kind",
    "method_sha256",
    "provider",
    "schema_version",
    "verification_nonce_sha256",
    "original_workspace_scope_sha256",
    "authenticated_workspace_identity_sha256",
    "reconciliation_authority_sha256",
}


class ReferenceSettlementError(ValueError):
    """Raised when pre-identity settlement evidence is incomplete or ambiguous."""


@dataclass(frozen=True)
class WorkspaceZeroSettlementEvidence:
    receipt_sha256: str
    report_sha256: str
    report_size_bytes: int
    recovery_authority_sha256: str
    original_workspace_scope_sha256: str
    authenticated_workspace_identity_sha256: str
    workspace_reconciliation_authority_sha256: str
    auth_binding_sha256: str
    pre_auth_receipt_sha256: str
    post_auth_receipt_sha256: str
    billing_authority_sha256: str
    billing_method_sha256: str
    report_identity_sha256: str
    reservation_id: str
    execution_scope_sha256: str
    query_start: datetime
    query_end: datetime
    acquired_at: datetime
    completeness_delay_seconds: int
    actual_cost_usd: str
    row_count: int


@dataclass(frozen=True)
class WorkspaceAuthReceiptEvidence:
    receipt_sha256: str
    authenticated_at: datetime
    original_workspace_scope_sha256: str
    authenticated_workspace_identity_sha256: str
    reconciliation_authority_sha256: str
    binding_sha256: str


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _parse_closed_json(content: bytes, *, label: str, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(content, bytes) or content.startswith(b"\xef\xbb\xbf"):
        raise ReferenceSettlementError(f"{label} must be canonical UTF-8 JSON")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReferenceSettlementError(f"{label} contains duplicate keys")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda name: (_ for _ in ()).throw(
                ReferenceSettlementError(f"{label} contains {name}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceSettlementError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReferenceSettlementError(f"{label} schema is closed")
    if content != _canonical_bytes(value):
        raise ReferenceSettlementError(f"{label} bytes are not canonical")
    return value


def _parse_receipt(content: bytes) -> Mapping[str, Any]:
    return _parse_closed_json(content, label="workspace-zero receipt", fields=_RECEIPT_FIELDS)


def _parse_auth_receipt(content: bytes, label: str) -> Mapping[str, Any]:
    value = _parse_closed_json(content, label=label, fields=_AUTH_RECEIPT_FIELDS)
    if (
        value["schema_version"] != 2
        or value["kind"] != "reference_modal_workspace_auth_receipt"
        or value["provider"] != "modal"
    ):
        raise ReferenceSettlementError(f"{label} identity is unsupported")
    return value


def validate_workspace_auth_receipt(
    content: bytes,
    *,
    expected_original_workspace_scope_sha256: str,
    expected_authenticated_workspace_identity_sha256: str,
    expected_reconciliation_authority_sha256: str,
    expected_binding_sha256: str,
    validated_at: datetime,
    maximum_age_seconds: int,
) -> WorkspaceAuthReceiptEvidence:
    """Validate one exact canonical provider-local authentication receipt snapshot."""
    receipt = _parse_auth_receipt(content, "workspace auth receipt")
    original_workspace = _expected_digest(
        receipt["original_workspace_scope_sha256"],
        expected_original_workspace_scope_sha256,
        "workspace auth receipt original workspace scope",
    )
    authenticated_identity = _expected_digest(
        receipt["authenticated_workspace_identity_sha256"],
        expected_authenticated_workspace_identity_sha256,
        "workspace auth receipt authenticated identity",
    )
    reconciliation = _expected_digest(
        receipt["reconciliation_authority_sha256"],
        expected_reconciliation_authority_sha256,
        "workspace auth receipt reconciliation authority",
    )
    if original_workspace == authenticated_identity:
        raise ReferenceSettlementError("workspace reconciliation must preserve distinct identities")
    binding = _expected_digest(
        receipt["binding_sha256"],
        expected_binding_sha256,
        "workspace auth receipt binding",
    )
    if receipt["method_sha256"] != AUTH_METHOD_SHA256:
        raise ReferenceSettlementError("workspace auth receipt method mismatch")
    _sha256(receipt["verification_nonce_sha256"], "workspace auth verification nonce")
    authenticated_at = _utc_timestamp(receipt["authenticated_at"], "authenticated_at")
    if validated_at.tzinfo is None or validated_at.utcoffset() is None:
        raise ReferenceSettlementError("workspace auth validation time must be timezone-aware")
    age = (validated_at.astimezone(UTC) - authenticated_at).total_seconds()
    if (
        not isinstance(maximum_age_seconds, int)
        or isinstance(maximum_age_seconds, bool)
        or maximum_age_seconds <= 0
        or age < 0
        or age > maximum_age_seconds
    ):
        raise ReferenceSettlementError("workspace auth receipt is stale or future-dated")
    return WorkspaceAuthReceiptEvidence(
        receipt_sha256=hashlib.sha256(content).hexdigest(),
        authenticated_at=authenticated_at,
        original_workspace_scope_sha256=original_workspace,
        authenticated_workspace_identity_sha256=authenticated_identity,
        reconciliation_authority_sha256=reconciliation,
        binding_sha256=binding,
    )


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReferenceSettlementError(f"{label} must be a lowercase SHA-256")
    return value


def _expected_digest(value: object, expected: str, label: str) -> str:
    digest = _sha256(value, label)
    if digest != _sha256(expected, f"expected {label}"):
        raise ReferenceSettlementError(f"{label} mismatch")
    return digest


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReferenceSettlementError(f"{label} must be an exact UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReferenceSettlementError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ReferenceSettlementError(f"{label} must be UTC")
    return parsed.astimezone(UTC)


def _hour_boundary(value: datetime) -> bool:
    return value.minute == value.second == value.microsecond == 0


def validate_workspace_zero_settlement_evidence(
    receipt_bytes: bytes,
    report_bytes: bytes,
    *,
    pre_auth_receipt_bytes: bytes,
    post_auth_receipt_bytes: bytes,
    expected_recovery_authority_sha256: str,
    expected_original_workspace_scope_sha256: str,
    expected_authenticated_workspace_identity_sha256: str,
    expected_workspace_reconciliation_authority_sha256: str,
    expected_billing_authority_sha256: str,
    expected_billing_method_sha256: str,
    expected_report_identity_sha256: str,
    expected_reservation_id: str,
    expected_execution_scope_sha256: str,
    latest_durable_boundary: datetime,
    validated_at: datetime,
    maximum_action_seconds: int,
    expected_completeness_delay_seconds: int,
) -> WorkspaceZeroSettlementEvidence:
    """Validate an exact empty complete workspace report without provider attribution."""
    receipt = _parse_receipt(receipt_bytes)
    if (
        receipt["schema_version"] != 2
        or receipt["kind"] != RECEIPT_KIND
        or receipt["provider"] != "modal"
    ):
        raise ReferenceSettlementError("workspace-zero receipt identity is unsupported")

    recovery = _expected_digest(
        receipt["recovery_authority_sha256"],
        expected_recovery_authority_sha256,
        "recovery authority",
    )
    original_workspace = _expected_digest(
        receipt["original_workspace_scope_sha256"],
        expected_original_workspace_scope_sha256,
        "original workspace scope",
    )
    authenticated_identity = _expected_digest(
        receipt["authenticated_workspace_identity_sha256"],
        expected_authenticated_workspace_identity_sha256,
        "authenticated workspace identity",
    )
    reconciliation = _expected_digest(
        receipt["workspace_reconciliation_authority_sha256"],
        expected_workspace_reconciliation_authority_sha256,
        "workspace reconciliation authority",
    )
    if original_workspace == authenticated_identity:
        raise ReferenceSettlementError("workspace reconciliation must preserve distinct identities")
    auth_binding = _sha256(receipt["auth_binding_sha256"], "auth binding")
    pre_auth = _sha256(receipt["pre_auth_receipt_sha256"], "pre-auth receipt")
    post_auth = _sha256(receipt["post_auth_receipt_sha256"], "post-auth receipt")
    if pre_auth == post_auth:
        raise ReferenceSettlementError("workspace-zero auth receipts must be distinct")
    pre_auth_receipt = _parse_auth_receipt(pre_auth_receipt_bytes, "pre-auth receipt")
    post_auth_receipt = _parse_auth_receipt(post_auth_receipt_bytes, "post-auth receipt")
    if hashlib.sha256(pre_auth_receipt_bytes).hexdigest() != pre_auth:
        raise ReferenceSettlementError("pre-auth receipt bytes do not match the receipt")
    if hashlib.sha256(post_auth_receipt_bytes).hexdigest() != post_auth:
        raise ReferenceSettlementError("post-auth receipt bytes do not match the receipt")
    for label, auth_receipt in (
        ("pre-auth", pre_auth_receipt),
        ("post-auth", post_auth_receipt),
    ):
        if auth_receipt["original_workspace_scope_sha256"] != original_workspace:
            raise ReferenceSettlementError(f"{label} original workspace scope mismatch")
        if auth_receipt["authenticated_workspace_identity_sha256"] != authenticated_identity:
            raise ReferenceSettlementError(f"{label} authenticated workspace identity mismatch")
        if auth_receipt["reconciliation_authority_sha256"] != reconciliation:
            raise ReferenceSettlementError(f"{label} reconciliation authority mismatch")
        if auth_receipt["binding_sha256"] != auth_binding:
            raise ReferenceSettlementError(f"{label} auth binding mismatch")
        if auth_receipt["method_sha256"] != AUTH_METHOD_SHA256:
            raise ReferenceSettlementError(f"{label} auth method mismatch")
        _sha256(auth_receipt["verification_nonce_sha256"], f"{label} verification nonce")
    billing_authority = _expected_digest(
        receipt["billing_authority_sha256"],
        expected_billing_authority_sha256,
        "billing authority",
    )
    billing_method = _expected_digest(
        receipt["billing_method_sha256"],
        expected_billing_method_sha256,
        "billing method",
    )
    report_identity = _expected_digest(
        receipt["authoritative_report_identity_sha256"],
        expected_report_identity_sha256,
        "authoritative report identity",
    )
    execution_scope = _expected_digest(
        receipt["original_execution_scope_sha256"],
        expected_execution_scope_sha256,
        "original execution scope",
    )
    reservation = receipt["reservation_id"]
    if (
        not isinstance(reservation, str)
        or _SAFE_ID_RE.fullmatch(reservation) is None
        or reservation != expected_reservation_id
    ):
        raise ReferenceSettlementError("workspace-zero reservation mismatch")
    if receipt["failure_code"] != FAILURE_CODE:
        raise ReferenceSettlementError("workspace-zero failure code mismatch")

    query_start = _utc_timestamp(receipt["query_start"], "query start")
    query_end = _utc_timestamp(receipt["query_end"], "query end")
    acquired_at = _utc_timestamp(receipt["acquired_at"], "acquired_at")
    pre_authenticated_at = _utc_timestamp(
        pre_auth_receipt["authenticated_at"], "pre-auth authenticated_at"
    )
    post_authenticated_at = _utc_timestamp(
        post_auth_receipt["authenticated_at"], "post-auth authenticated_at"
    )
    if not pre_authenticated_at <= post_authenticated_at <= acquired_at:
        raise ReferenceSettlementError("workspace-zero auth receipt ordering is invalid")
    if (
        (acquired_at - pre_authenticated_at).total_seconds()
        > AUTH_RECEIPT_MAXIMUM_AGE_SECONDS
        or (acquired_at - post_authenticated_at).total_seconds()
        > AUTH_RECEIPT_MAXIMUM_AGE_SECONDS
    ):
        raise ReferenceSettlementError("workspace-zero auth receipt is stale")
    if not _hour_boundary(query_start) or not _hour_boundary(query_end) or query_start >= query_end:
        raise ReferenceSettlementError("workspace-zero query interval must contain full hours")
    if latest_durable_boundary.tzinfo is None or latest_durable_boundary.utcoffset() is None:
        raise ReferenceSettlementError("latest durable boundary must be timezone-aware")
    if (
        not isinstance(maximum_action_seconds, int)
        or isinstance(maximum_action_seconds, bool)
        or maximum_action_seconds <= 0
    ):
        raise ReferenceSettlementError("maximum action seconds must be positive")
    required_end = latest_durable_boundary.astimezone(UTC) + timedelta(
        seconds=maximum_action_seconds
    )
    if query_start > latest_durable_boundary.astimezone(UTC) or query_end < required_end:
        raise ReferenceSettlementError("workspace-zero query does not cover the full action window")
    delay = receipt["completeness_delay_seconds"]
    if (
        not isinstance(delay, int)
        or isinstance(delay, bool)
        or delay <= 0
        or delay != expected_completeness_delay_seconds
    ):
        raise ReferenceSettlementError("workspace-zero completeness delay must be positive")
    if acquired_at < query_end + timedelta(seconds=delay):
        raise ReferenceSettlementError("workspace-zero acquisition precedes completeness delay")
    if validated_at.tzinfo is None or validated_at.utcoffset() is None:
        raise ReferenceSettlementError("validation time must be timezone-aware")
    if acquired_at > validated_at.astimezone(UTC):
        raise ReferenceSettlementError("workspace-zero evidence was acquired in the future")

    if receipt["actual_cost_usd"] != "0":
        raise ReferenceSettlementError("workspace-zero cost must be exact zero, not rounded zero")
    if receipt["currency"] != "USD":
        raise ReferenceSettlementError("workspace-zero currency must be USD")
    if (
        receipt["row_count"] != 0
        or receipt["pagination_complete"] is not True
        or receipt["filters"] != []
        or receipt["all_environments"] is not True
        or receipt["all_resources"] is not True
    ):
        if receipt["row_count"] != 0:
            raise ReferenceSettlementError("workspace-zero report must be empty")
        if receipt["pagination_complete"] is not True:
            raise ReferenceSettlementError("workspace-zero pagination must be complete")
        raise ReferenceSettlementError("workspace-zero report must be unfiltered")
    if not isinstance(report_bytes, bytes):
        raise ReferenceSettlementError("workspace-zero report bytes are invalid")
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    if receipt["report_sha256"] != report_sha256 or receipt["report_size_bytes"] != len(
        report_bytes
    ):
        raise ReferenceSettlementError("workspace-zero report bytes do not match the receipt")
    if report_bytes != CANONICAL_EMPTY_REPORT:
        raise ReferenceSettlementError("workspace-zero report must be the canonical empty array")

    return WorkspaceZeroSettlementEvidence(
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        report_sha256=report_sha256,
        report_size_bytes=len(report_bytes),
        recovery_authority_sha256=recovery,
        original_workspace_scope_sha256=original_workspace,
        authenticated_workspace_identity_sha256=authenticated_identity,
        workspace_reconciliation_authority_sha256=reconciliation,
        auth_binding_sha256=auth_binding,
        pre_auth_receipt_sha256=pre_auth,
        post_auth_receipt_sha256=post_auth,
        billing_authority_sha256=billing_authority,
        billing_method_sha256=billing_method,
        report_identity_sha256=report_identity,
        reservation_id=reservation,
        execution_scope_sha256=execution_scope,
        query_start=query_start,
        query_end=query_end,
        acquired_at=acquired_at,
        completeness_delay_seconds=delay,
        actual_cost_usd="0",
        row_count=0,
    )
