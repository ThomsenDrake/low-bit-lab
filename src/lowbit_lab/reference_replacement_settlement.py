"""Pure validation for the sole app-attributed replacement U8 settlement."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation

from lowbit_lab.config import SHA256_RE
from lowbit_lab.reference_settlement import (
    AUTH_RECEIPT_MAXIMUM_AGE_SECONDS,
    ReferenceSettlementError,
    validate_workspace_auth_receipt,
)

APP_KIND = "reference_replacement_stopped_app_evidence"
REPORT_KIND = "reference_replacement_filtered_billing_report"
RECEIPT_KIND = "reference_replacement_billing_settlement"
_APP_ID_RE = re.compile(r"ap-[A-Za-z0-9]{22}")
_APP_FIELDS = {
    "app_id",
    "created_at",
    "kind",
    "schema_version",
    "state",
    "stopped_at",
    "running_tasks",
}
_REPORT_FIELDS = {"kind", "rows", "schema_version"}
_ROW_FIELDS = {"cost", "interval_start", "object_id", "resource"}
_RECEIPT_FIELDS = {
    "acquired_at",
    "actual_cost_usd",
    "app_evidence_sha256",
    "authenticated_workspace_identity_sha256",
    "auth_binding_sha256",
    "authoritative_report_identity_sha256",
    "billing_authority_sha256",
    "billing_method_sha256",
    "completeness_delay_seconds",
    "entitlement_sha256",
    "environment_scope_sha256",
    "execution_scope_sha256",
    "filtered_report_sha256",
    "filtered_report_size_bytes",
    "kind",
    "post_auth_receipt_sha256",
    "pre_auth_receipt_sha256",
    "provider",
    "query_end",
    "query_start",
    "reservation_id",
    "schema_version",
}


class ReplacementSettlementError(ValueError):
    """Raised when replacement billing evidence is incomplete or ambiguous."""


@dataclass(frozen=True)
class ReplacementSettlementEvidence:
    receipt_sha256: str
    app_id: str
    actual_cost_usd: str
    acquired_at: datetime
    query_end: datetime


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _closed(content: bytes, fields: set[str], label: str) -> Mapping[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReplacementSettlementError(f"{label} is not valid JSON") from exc
    if not isinstance(value, Mapping) or set(value) != fields or canonical_bytes(value) != content:
        raise ReplacementSettlementError(f"{label} schema or bytes drift")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReplacementSettlementError(f"{label} must be SHA-256")
    return value


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReplacementSettlementError(f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplacementSettlementError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ReplacementSettlementError(f"{label} must be UTC")
    return parsed.astimezone(UTC)


def _money(value: object, label: str) -> Decimal:
    try:
        parsed = Decimal(value) if isinstance(value, str) else Decimal("NaN")
    except InvalidOperation as exc:
        raise ReplacementSettlementError(f"{label} is invalid") from exc
    if not parsed.is_finite() or parsed < 0 or parsed.as_tuple().exponent < -10:
        raise ReplacementSettlementError(f"{label} is invalid")
    return parsed


def validate_replacement_settlement(
    receipt_bytes: bytes,
    app_evidence_bytes: bytes,
    filtered_report_bytes: bytes,
    *,
    pre_auth_receipt_bytes: bytes,
    post_auth_receipt_bytes: bytes,
    expected_reservation_id: str,
    expected_execution_scope_sha256: str,
    expected_entitlement_sha256: str,
    expected_environment_scope_sha256: str,
    expected_original_workspace_scope_sha256: str,
    expected_workspace_identity_sha256: str,
    expected_reconciliation_authority_sha256: str,
    expected_auth_binding_sha256: str,
    expected_billing_authority_sha256: str,
    expected_billing_method_sha256: str,
    expected_report_identity_sha256: str,
    action_consumed_at: datetime,
    latest_boundary_at: datetime,
    maximum_action_seconds: int,
    expected_completeness_delay_seconds: int,
    validated_at: datetime,
) -> ReplacementSettlementEvidence:
    receipt = _closed(receipt_bytes, _RECEIPT_FIELDS, "replacement receipt")
    app = _closed(app_evidence_bytes, _APP_FIELDS, "app evidence")
    report = _closed(filtered_report_bytes, _REPORT_FIELDS, "filtered billing report")
    if (
        type(receipt["schema_version"]) is not int
        or type(app["schema_version"]) is not int
        or type(report["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["kind"] != RECEIPT_KIND
        or receipt["provider"] != "modal"
        or app["schema_version"] != 1
        or app["kind"] != APP_KIND
        or report["schema_version"] != 1
        or report["kind"] != REPORT_KIND
    ):
        raise ReplacementSettlementError("replacement evidence identity drift")
    expected = {
        "reservation_id": expected_reservation_id,
        "execution_scope_sha256": expected_execution_scope_sha256,
        "entitlement_sha256": expected_entitlement_sha256,
        "environment_scope_sha256": expected_environment_scope_sha256,
        "authenticated_workspace_identity_sha256": expected_workspace_identity_sha256,
        "auth_binding_sha256": expected_auth_binding_sha256,
        "billing_authority_sha256": expected_billing_authority_sha256,
        "billing_method_sha256": expected_billing_method_sha256,
        "authoritative_report_identity_sha256": expected_report_identity_sha256,
    }
    if any(receipt[key] != value for key, value in expected.items()):
        raise ReplacementSettlementError("replacement settlement lineage mismatch")
    for key in (
        "execution_scope_sha256",
        "entitlement_sha256",
        "environment_scope_sha256",
        "authenticated_workspace_identity_sha256",
        "auth_binding_sha256",
        "billing_authority_sha256",
        "billing_method_sha256",
        "authoritative_report_identity_sha256",
        "app_evidence_sha256",
        "filtered_report_sha256",
        "pre_auth_receipt_sha256",
        "post_auth_receipt_sha256",
    ):
        _sha(receipt[key], key)
    if hashlib.sha256(app_evidence_bytes).hexdigest() != receipt["app_evidence_sha256"]:
        raise ReplacementSettlementError("app evidence hash mismatch")
    if (
        hashlib.sha256(filtered_report_bytes).hexdigest() != receipt["filtered_report_sha256"]
        or type(receipt["filtered_report_size_bytes"]) is not int
        or len(filtered_report_bytes) != receipt["filtered_report_size_bytes"]
    ):
        raise ReplacementSettlementError("filtered report byte binding mismatch")
    if receipt["pre_auth_receipt_sha256"] == receipt["post_auth_receipt_sha256"]:
        raise ReplacementSettlementError("replacement auth receipts must be distinct")
    acquired = _time(receipt["acquired_at"], "acquired_at")
    query_start = _time(receipt["query_start"], "query_start")
    query_end = _time(receipt["query_end"], "query_end")
    if (
        query_start >= query_end
        or any((query_start.minute, query_start.second, query_start.microsecond))
        or any((query_end.minute, query_end.second, query_end.microsecond))
        or query_start > action_consumed_at
        or query_end < latest_boundary_at + timedelta(seconds=maximum_action_seconds)
        or type(receipt["completeness_delay_seconds"]) is not int
        or type(expected_completeness_delay_seconds) is not int
        or expected_completeness_delay_seconds != receipt["completeness_delay_seconds"]
        or acquired < query_end + timedelta(seconds=expected_completeness_delay_seconds)
        or validated_at < acquired
    ):
        raise ReplacementSettlementError("replacement billing window is incomplete")
    app_id = app["app_id"]
    if not isinstance(app_id, str) or _APP_ID_RE.fullmatch(app_id) is None:
        raise ReplacementSettlementError("app identity is invalid")
    created = _time(app["created_at"], "app created_at")
    stopped = _time(app["stopped_at"], "app stopped_at")
    if (
        app["state"] != "stopped"
        or type(app["running_tasks"]) is not int
        or app["running_tasks"] != 0
        or created < action_consumed_at
        or stopped < created
        or stopped > action_consumed_at + timedelta(seconds=maximum_action_seconds)
    ):
        raise ReplacementSettlementError("stopped app evidence is inconsistent")
    rows = report["rows"]
    if not isinstance(rows, list):
        raise ReplacementSettlementError("filtered billing rows are invalid")
    total = Decimal("0")
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _ROW_FIELDS or row["object_id"] != app_id:
            raise ReplacementSettlementError("filtered billing row identity drift")
        interval = _time(row["interval_start"], "billing interval")
        if interval < query_start or interval >= query_end or not isinstance(row["resource"], str):
            raise ReplacementSettlementError("filtered billing interval drift")
        total += _money(row["cost"], "billing row cost")
    actual = _money(receipt["actual_cost_usd"], "actual cost")
    if total != actual:
        raise ReplacementSettlementError("filtered billing total mismatch")
    auth_evidence = []
    for content, digest, label in (
        (pre_auth_receipt_bytes, receipt["pre_auth_receipt_sha256"], "pre-auth"),
        (post_auth_receipt_bytes, receipt["post_auth_receipt_sha256"], "post-auth"),
    ):
        if hashlib.sha256(content).hexdigest() != digest:
            raise ReplacementSettlementError(f"{label} bytes mismatch")
        try:
            auth_evidence.append(
                validate_workspace_auth_receipt(
                    content,
                    expected_original_workspace_scope_sha256=(
                        expected_original_workspace_scope_sha256
                    ),
                    expected_authenticated_workspace_identity_sha256=(
                        expected_workspace_identity_sha256
                    ),
                    expected_reconciliation_authority_sha256=(
                        expected_reconciliation_authority_sha256
                    ),
                    expected_binding_sha256=expected_auth_binding_sha256,
                    validated_at=acquired,
                    maximum_age_seconds=AUTH_RECEIPT_MAXIMUM_AGE_SECONDS,
                )
            )
        except ReferenceSettlementError as exc:
            raise ReplacementSettlementError(f"{label} evidence is invalid") from exc
    if auth_evidence[0].authenticated_at > auth_evidence[1].authenticated_at:
        raise ReplacementSettlementError("replacement auth receipt ordering is invalid")
    return ReplacementSettlementEvidence(
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        app_id=app_id,
        actual_cost_usd=str(receipt["actual_cost_usd"]),
        acquired_at=acquired,
        query_end=query_end,
    )
