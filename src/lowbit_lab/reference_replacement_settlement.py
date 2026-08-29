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
BILLING_APP_KIND = "reference_replacement_billing_app_identity"
REPORT_KIND = "reference_replacement_filtered_billing_report"
RECEIPT_KIND = "reference_replacement_billing_settlement"
ADDITIONAL_RECEIPT_KIND = "reference_additional_billing_settlement"
ADDITIONAL_REPORT_KIND = "reference_additional_filtered_billing_report"
_APP_ID_RE = re.compile(r"ap-[A-Za-z0-9]{22}")
_CALL_ID_RE = re.compile(r"fc-[A-Za-z0-9]{22}")
_APP_FIELDS = {
    "app_id",
    "created_at",
    "kind",
    "schema_version",
    "state",
    "stopped_at",
    "running_tasks",
}
_BILLING_APP_FIELDS = {
    "app_id",
    "identity_source",
    "kind",
    "recent_app_listing",
    "schema_version",
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


@dataclass(frozen=True)
class AdditionalSettlementEvidence:
    """Validated billing facts for the append-only additional U8 grant."""

    receipt_sha256: str
    actual_cost_usd: str
    acquired_at: datetime
    query_end: datetime
    attribution_mode: str
    provider_identity: str | None
    execution_receipt_sha256: str | None
    execution_manifest_sha256: str | None


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _canonical_mapping(content: bytes, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReplacementSettlementError(f"{label} is not valid JSON") from exc
    if not isinstance(value, Mapping) or canonical_bytes(value) != content:
        raise ReplacementSettlementError(f"{label} schema or bytes drift")
    return value


def _closed(content: bytes, fields: set[str], label: str) -> Mapping[str, object]:
    value = _canonical_mapping(content, label)
    if set(value) != fields:
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
    app = _canonical_mapping(app_evidence_bytes, "app evidence")
    billing_only_app = (
        app.get("schema_version") == 2 and app.get("kind") == BILLING_APP_KIND
    )
    expected_app_fields = _BILLING_APP_FIELDS if billing_only_app else _APP_FIELDS
    if set(app) != expected_app_fields:
        raise ReplacementSettlementError("app evidence schema or bytes drift")
    report = _closed(filtered_report_bytes, _REPORT_FIELDS, "filtered billing report")
    if (
        type(receipt["schema_version"]) is not int
        or type(app["schema_version"]) is not int
        or type(report["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["kind"] != RECEIPT_KIND
        or receipt["provider"] != "modal"
        or (
            not billing_only_app
            and (app["schema_version"] != 1 or app["kind"] != APP_KIND)
        )
        or (
            billing_only_app
            and (
                app["identity_source"] != "authoritative_filtered_billing_report"
                or app["recent_app_listing"] != "not_returned"
            )
        )
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
    if not billing_only_app:
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
    if not isinstance(rows, list) or (billing_only_app and not rows):
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


_ADDITIONAL_IDENTITY_FIELDS = {
    "identity_source",
    "kind",
    "provider_identity",
    "schema_version",
}
_ADDITIONAL_REPORT_FIELDS = {"kind", "rows", "schema_version"}
_ADDITIONAL_RECEIPT_FIELDS = {
    "acquired_at",
    "actual_cost_usd",
    "additional_authority_sha256",
    "attribution_mode",
    "authenticated_workspace_identity_sha256",
    "authoritative_report_identity_sha256",
    "billing_authority_sha256",
    "billing_method_sha256",
    "captured_at",
    "completeness_delay_seconds",
    "environment_scope_sha256",
    "execution_manifest_sha256",
    "execution_receipt_sha256",
    "execution_scope_sha256",
    "filtered_report_sha256",
    "filtered_report_size_bytes",
    "identity_evidence_sha256",
    "kind",
    "post_auth_receipt_sha256",
    "pre_auth_receipt_sha256",
    "provider",
    "query_end",
    "query_start",
    "reservation_id",
    "schema_version",
}
_ADDITIONAL_MODES = {
    "app",
    "billing_only",
    "call",
    "workspace_zero_preidentity",
}
_ADDITIONAL_IDENTITY_KINDS = {
    "app": ("reference_additional_app_identity", "durable_app_identity"),
    "billing_only": (
        "reference_additional_billing_identity",
        "authoritative_filtered_billing_report",
    ),
    "call": ("reference_additional_call_identity", "durable_call_identity"),
    "workspace_zero_preidentity": (
        "reference_additional_workspace_zero_identity",
        "complete_workspace_billing",
    ),
}


def validate_additional_settlement(
    receipt_bytes: bytes,
    identity_evidence_bytes: bytes,
    filtered_report_bytes: bytes,
    *,
    pre_auth_receipt_bytes: bytes,
    post_auth_receipt_bytes: bytes,
    expected_reservation_id: str,
    expected_execution_scope_sha256: str,
    expected_additional_authority_sha256: str,
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
) -> AdditionalSettlementEvidence:
    """Validate one exhaustive, replay-safe settlement for the final U8 grant."""
    receipt = _closed(receipt_bytes, _ADDITIONAL_RECEIPT_FIELDS, "additional receipt")
    identity = _closed(
        identity_evidence_bytes,
        _ADDITIONAL_IDENTITY_FIELDS,
        "additional identity evidence",
    )
    report = _closed(
        filtered_report_bytes,
        _ADDITIONAL_REPORT_FIELDS,
        "additional filtered billing report",
    )
    mode = receipt["attribution_mode"]
    if (
        type(receipt["schema_version"]) is not int
        or type(identity["schema_version"]) is not int
        or type(report["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or identity["schema_version"] != 1
        or report["schema_version"] != 1
        or receipt["kind"] != ADDITIONAL_RECEIPT_KIND
        or receipt["provider"] != "modal"
        or report["kind"] != ADDITIONAL_REPORT_KIND
        or mode not in _ADDITIONAL_MODES
    ):
        raise ReplacementSettlementError("additional settlement identity drift")
    expected_kind, expected_source = _ADDITIONAL_IDENTITY_KINDS[str(mode)]
    provider_identity = identity["provider_identity"]
    if (
        identity["kind"] != expected_kind
        or identity["identity_source"] != expected_source
        or (
            mode == "workspace_zero_preidentity"
            and provider_identity is not None
        )
        or (
            mode != "workspace_zero_preidentity"
            and (not isinstance(provider_identity, str) or not provider_identity)
        )
    ):
        raise ReplacementSettlementError("additional provider identity is invalid")
    call_identity_valid = isinstance(provider_identity, str) and bool(
        _CALL_ID_RE.fullmatch(provider_identity)
    )
    app_identity_valid = isinstance(provider_identity, str) and bool(
        _APP_ID_RE.fullmatch(provider_identity)
    )
    if (mode == "call" and not call_identity_valid) or (
        mode in {"app", "billing_only"} and not app_identity_valid
    ):
        raise ReplacementSettlementError("additional provider identity is invalid")
    expected = {
        "reservation_id": expected_reservation_id,
        "execution_scope_sha256": expected_execution_scope_sha256,
        "additional_authority_sha256": expected_additional_authority_sha256,
        "environment_scope_sha256": expected_environment_scope_sha256,
        "authenticated_workspace_identity_sha256": expected_workspace_identity_sha256,
        "billing_authority_sha256": expected_billing_authority_sha256,
        "billing_method_sha256": expected_billing_method_sha256,
        "authoritative_report_identity_sha256": expected_report_identity_sha256,
    }
    if any(receipt[key] != value for key, value in expected.items()):
        raise ReplacementSettlementError("additional settlement lineage mismatch")
    for key in (
        "execution_scope_sha256",
        "additional_authority_sha256",
        "environment_scope_sha256",
        "authenticated_workspace_identity_sha256",
        "billing_authority_sha256",
        "billing_method_sha256",
        "authoritative_report_identity_sha256",
        "identity_evidence_sha256",
        "filtered_report_sha256",
        "pre_auth_receipt_sha256",
        "post_auth_receipt_sha256",
    ):
        _sha(receipt[key], key)
    for key in ("execution_receipt_sha256", "execution_manifest_sha256"):
        if receipt[key] is not None:
            _sha(receipt[key], key)
    if hashlib.sha256(identity_evidence_bytes).hexdigest() != receipt["identity_evidence_sha256"]:
        raise ReplacementSettlementError("additional identity evidence hash mismatch")
    if (
        hashlib.sha256(filtered_report_bytes).hexdigest() != receipt["filtered_report_sha256"]
        or type(receipt["filtered_report_size_bytes"]) is not int
        or len(filtered_report_bytes) != receipt["filtered_report_size_bytes"]
    ):
        raise ReplacementSettlementError("additional report byte binding mismatch")
    if receipt["pre_auth_receipt_sha256"] == receipt["post_auth_receipt_sha256"]:
        raise ReplacementSettlementError("additional auth receipts must be distinct")
    acquired = _time(receipt["acquired_at"], "acquired_at")
    captured = _time(receipt["captured_at"], "captured_at")
    query_start = _time(receipt["query_start"], "query_start")
    query_end = _time(receipt["query_end"], "query_end")
    if (
        query_start >= query_end
        or any((query_start.minute, query_start.second, query_start.microsecond))
        or any((query_end.minute, query_end.second, query_end.microsecond))
        or query_start > action_consumed_at
        or query_end < latest_boundary_at + timedelta(seconds=maximum_action_seconds)
        or type(receipt["completeness_delay_seconds"]) is not int
        or receipt["completeness_delay_seconds"] != expected_completeness_delay_seconds
        or acquired < query_end + timedelta(seconds=expected_completeness_delay_seconds)
        or captured > acquired
        or validated_at < acquired
    ):
        raise ReplacementSettlementError("additional billing window is incomplete")
    rows = report["rows"]
    if not isinstance(rows, list):
        raise ReplacementSettlementError("additional billing rows are invalid")
    total = Decimal("0")
    identities: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _ROW_FIELDS:
            raise ReplacementSettlementError("additional billing row schema drift")
        interval = _time(row["interval_start"], "billing interval")
        if interval < query_start or interval >= query_end or not isinstance(row["resource"], str):
            raise ReplacementSettlementError("additional billing interval drift")
        if not isinstance(row["object_id"], str) or not row["object_id"]:
            raise ReplacementSettlementError("additional billing row identity drift")
        identities.add(row["object_id"])
        total += _money(row["cost"], "billing row cost")
    actual = _money(receipt["actual_cost_usd"], "actual cost")
    if total != actual:
        raise ReplacementSettlementError("additional billing total mismatch")
    if mode == "workspace_zero_preidentity":
        if rows or actual != 0 or receipt["execution_receipt_sha256"] is not None:
            raise ReplacementSettlementError("workspace-zero evidence is not exact zero")
    elif not rows or identities != {provider_identity}:
        raise ReplacementSettlementError("additional billing identity is ambiguous")
    if mode in {"billing_only", "workspace_zero_preidentity"} and receipt[
        "execution_receipt_sha256"
    ] is not None:
        raise ReplacementSettlementError("pre-identity evidence cannot claim execution")
    if receipt["execution_manifest_sha256"] is not None and receipt[
        "execution_receipt_sha256"
    ] is None:
        raise ReplacementSettlementError("execution manifest lacks its receipt")
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
    if not (
        auth_evidence[0].authenticated_at
        <= captured
        <= auth_evidence[1].authenticated_at
        <= acquired
    ):
        raise ReplacementSettlementError("additional auth receipt ordering is invalid")
    return AdditionalSettlementEvidence(
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        actual_cost_usd=str(receipt["actual_cost_usd"]),
        acquired_at=acquired,
        query_end=query_end,
        attribution_mode=str(mode),
        provider_identity=None if provider_identity is None else str(provider_identity),
        execution_receipt_sha256=(
            None
            if receipt["execution_receipt_sha256"] is None
            else str(receipt["execution_receipt_sha256"])
        ),
        execution_manifest_sha256=(
            None
            if receipt["execution_manifest_sha256"] is None
            else str(receipt["execution_manifest_sha256"])
        ),
    )
