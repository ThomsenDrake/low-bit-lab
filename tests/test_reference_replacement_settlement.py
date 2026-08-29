from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from lowbit_lab.reference_replacement_settlement import (
    ADDITIONAL_RECEIPT_KIND,
    ADDITIONAL_REPORT_KIND,
    APP_KIND,
    RECEIPT_KIND,
    REPORT_KIND,
    ReplacementSettlementError,
    canonical_bytes,
    validate_additional_settlement,
    validate_replacement_settlement,
)
from lowbit_lab.reference_settlement import AUTH_METHOD_SHA256

DIGESTS = {
    name: char * 64
    for name, char in zip(
        (
            "scope",
            "entitlement",
            "environment",
            "original",
            "workspace",
            "reconciliation",
            "binding",
            "billing",
            "method",
            "report",
        ),
        "123456789a",
        strict=True,
    )
}


def _auth(nonce: str, authenticated_at: str = "2026-08-27T17:00:30+00:00") -> bytes:
    return canonical_bytes(
        {
            "authenticated_at": authenticated_at,
            "authenticated_workspace_identity_sha256": DIGESTS["workspace"],
            "binding_sha256": DIGESTS["binding"],
            "kind": "reference_modal_workspace_auth_receipt",
            "method_sha256": AUTH_METHOD_SHA256,
            "original_workspace_scope_sha256": DIGESTS["original"],
            "provider": "modal",
            "reconciliation_authority_sha256": DIGESTS["reconciliation"],
            "schema_version": 2,
            "verification_nonce_sha256": nonce * 64,
        }
    )


def _evidence(*, billing_only: bool = False) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    app_id = "ap-" + "A" * 22
    app_value = (
        {
            "app_id": app_id,
            "identity_source": "authoritative_filtered_billing_report",
            "kind": "reference_replacement_billing_app_identity",
            "recent_app_listing": "not_returned",
            "schema_version": 2,
        }
        if billing_only
        else {
            "app_id": app_id,
            "created_at": "2026-08-27T14:28:16+00:00",
            "kind": APP_KIND,
            "schema_version": 1,
            "state": "stopped",
            "stopped_at": "2026-08-27T14:29:28+00:00",
            "running_tasks": 0,
        }
    )
    app = canonical_bytes(app_value)
    report = canonical_bytes(
        {
            "kind": REPORT_KIND,
            "rows": [
                {
                    "cost": "0.125",
                    "interval_start": "2026-08-27T14:00:00+00:00",
                    "object_id": app_id,
                    "resource": "cpu",
                },
                {
                    "cost": "0.25",
                    "interval_start": "2026-08-27T14:00:00+00:00",
                    "object_id": app_id,
                    "resource": "memory",
                },
            ],
            "schema_version": 1,
        }
    )
    pre, post = _auth("a"), _auth("b")
    receipt = canonical_bytes(
        {
            "acquired_at": "2026-08-27T17:01:00+00:00",
            "actual_cost_usd": "0.375",
            "app_evidence_sha256": hashlib.sha256(app).hexdigest(),
            "authenticated_workspace_identity_sha256": DIGESTS["workspace"],
            "auth_binding_sha256": DIGESTS["binding"],
            "authoritative_report_identity_sha256": DIGESTS["report"],
            "billing_authority_sha256": DIGESTS["billing"],
            "billing_method_sha256": DIGESTS["method"],
            "completeness_delay_seconds": 3600,
            "entitlement_sha256": DIGESTS["entitlement"],
            "environment_scope_sha256": DIGESTS["environment"],
            "execution_scope_sha256": DIGESTS["scope"],
            "filtered_report_sha256": hashlib.sha256(report).hexdigest(),
            "filtered_report_size_bytes": len(report),
            "kind": RECEIPT_KIND,
            "post_auth_receipt_sha256": hashlib.sha256(post).hexdigest(),
            "pre_auth_receipt_sha256": hashlib.sha256(pre).hexdigest(),
            "provider": "modal",
            "query_end": "2026-08-27T16:00:00+00:00",
            "query_start": "2026-08-27T14:00:00+00:00",
            "reservation_id": "replacement-one",
            "schema_version": 1,
        }
    )
    return receipt, app, report, pre, post


def _validate(parts: tuple[bytes, bytes, bytes, bytes, bytes]):
    receipt, app, report, pre, post = parts
    return validate_replacement_settlement(
        receipt,
        app,
        report,
        pre_auth_receipt_bytes=pre,
        post_auth_receipt_bytes=post,
        expected_reservation_id="replacement-one",
        expected_execution_scope_sha256=DIGESTS["scope"],
        expected_entitlement_sha256=DIGESTS["entitlement"],
        expected_environment_scope_sha256=DIGESTS["environment"],
        expected_original_workspace_scope_sha256=DIGESTS["original"],
        expected_workspace_identity_sha256=DIGESTS["workspace"],
        expected_reconciliation_authority_sha256=DIGESTS["reconciliation"],
        expected_auth_binding_sha256=DIGESTS["binding"],
        expected_billing_authority_sha256=DIGESTS["billing"],
        expected_billing_method_sha256=DIGESTS["method"],
        expected_report_identity_sha256=DIGESTS["report"],
        action_consumed_at=datetime(2026, 8, 27, 14, 27, 54, tzinfo=UTC),
        latest_boundary_at=datetime(2026, 8, 27, 14, 29, 27, tzinfo=UTC),
        maximum_action_seconds=2700,
        expected_completeness_delay_seconds=3600,
        validated_at=datetime(2026, 8, 27, 17, 1, 1, tzinfo=UTC),
    )


def test_complete_replacement_evidence_binds_app_cost_and_bytes() -> None:
    evidence = _validate(_evidence())
    assert evidence.app_id == "ap-" + "A" * 22
    assert evidence.actual_cost_usd == "0.375"


def test_billing_only_app_identity_avoids_fabricated_lifecycle_claims() -> None:
    parts = _evidence(billing_only=True)
    evidence = _validate(parts)
    app = json.loads(parts[1])
    assert evidence.app_id == "ap-" + "A" * 22
    assert app["recent_app_listing"] == "not_returned"
    assert "state" not in app
    assert "running_tasks" not in app
    assert "created_at" not in app
    assert "stopped_at" not in app


@pytest.mark.parametrize("mutation", ["cost", "app", "window", "early", "lineage"])
def test_replacement_evidence_fails_closed(mutation: str) -> None:
    receipt, app, report, pre, post = _evidence()
    if mutation == "cost":
        raw = json.loads(receipt)
        raw["actual_cost_usd"] = "0.374"
        receipt = canonical_bytes(raw)
    elif mutation == "app":
        raw = json.loads(app)
        raw["running_tasks"] = 1
        app = canonical_bytes(raw)
    elif mutation == "window":
        raw = json.loads(receipt)
        raw["query_end"] = "2026-08-27T15:00:00+00:00"
        receipt = canonical_bytes(raw)
    elif mutation == "early":
        raw = json.loads(receipt)
        raw["acquired_at"] = "2026-08-27T16:59:59+00:00"
        receipt = canonical_bytes(raw)
    else:
        raw = json.loads(receipt)
        raw["entitlement_sha256"] = "f" * 64
        receipt = canonical_bytes(raw)
    with pytest.raises(ReplacementSettlementError):
        _validate((receipt, app, report, pre, post))


@pytest.mark.parametrize("mutation", ["same", "reversed"])
def test_replacement_authentication_must_bracket_capture(mutation: str) -> None:
    receipt, app, report, pre, post = _evidence()
    raw = json.loads(receipt)
    if mutation == "same":
        post = pre
    else:
        pre = _auth("a", "2026-08-27T17:00:40+00:00")
        post = _auth("b", "2026-08-27T17:00:20+00:00")
    raw["pre_auth_receipt_sha256"] = hashlib.sha256(pre).hexdigest()
    raw["post_auth_receipt_sha256"] = hashlib.sha256(post).hexdigest()
    receipt = canonical_bytes(raw)
    with pytest.raises(ReplacementSettlementError, match="auth"):
        _validate((receipt, app, report, pre, post))


def test_nested_auth_validation_uses_replacement_error_contract() -> None:
    receipt, app, report, pre, post = _evidence()
    nested = json.loads(pre)
    nested["binding_sha256"] = "f" * 64
    pre = canonical_bytes(nested)
    raw = json.loads(receipt)
    raw["pre_auth_receipt_sha256"] = hashlib.sha256(pre).hexdigest()
    receipt = canonical_bytes(raw)

    with pytest.raises(ReplacementSettlementError, match="pre-auth evidence"):
        _validate((receipt, app, report, pre, post))


@pytest.mark.parametrize(
    ("artifact", "field", "value"),
    [
        ("receipt", "schema_version", True),
        ("receipt", "schema_version", 1.0),
        ("receipt", "filtered_report_size_bytes", 1.0),
        ("receipt", "completeness_delay_seconds", 3600.0),
        ("app", "schema_version", True),
        ("app", "schema_version", 1.0),
        ("report", "schema_version", True),
        ("report", "schema_version", 1.0),
        ("app", "running_tasks", False),
    ],
)
def test_replacement_integer_fields_reject_type_drift(
    artifact: str, field: str, value: object
) -> None:
    receipt, app, report, pre, post = _evidence()
    parts = {
        "receipt": json.loads(receipt),
        "app": json.loads(app),
        "report": json.loads(report),
    }
    parts[artifact][field] = value
    app = canonical_bytes(parts["app"])
    report = canonical_bytes(parts["report"])
    parts["receipt"]["app_evidence_sha256"] = hashlib.sha256(app).hexdigest()
    parts["receipt"]["filtered_report_sha256"] = hashlib.sha256(report).hexdigest()
    parts["receipt"]["filtered_report_size_bytes"] = len(report)
    if artifact == "receipt":
        parts["receipt"][field] = value
    receipt = canonical_bytes(parts["receipt"])
    with pytest.raises(ReplacementSettlementError):
        _validate((receipt, app, report, pre, post))


def _additional_evidence(
    mode: str = "call", *, actual_cost: str = "0.375"
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    provider_identity = None if mode == "workspace_zero_preidentity" else "fc-" + "A" * 22
    if mode in {"app", "billing_only"}:
        provider_identity = "ap-" + "A" * 22
    kind, source = {
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
    }[mode]
    identity = canonical_bytes(
        {
            "identity_source": source,
            "kind": kind,
            "provider_identity": provider_identity,
            "schema_version": 1,
        }
    )
    rows = []
    if provider_identity is not None:
        rows = [
            {
                "cost": actual_cost,
                "interval_start": "2026-08-27T14:00:00+00:00",
                "object_id": provider_identity,
                "resource": "gpu",
            }
        ]
    report = canonical_bytes(
        {"kind": ADDITIONAL_REPORT_KIND, "rows": rows, "schema_version": 1}
    )
    pre, post = _auth("a"), _auth("b")
    execution_receipt = None if mode in {"billing_only", "workspace_zero_preidentity"} else "b" * 64
    receipt = canonical_bytes(
        {
            "acquired_at": "2026-08-27T17:01:00+00:00",
            "actual_cost_usd": "0" if mode == "workspace_zero_preidentity" else actual_cost,
            "additional_authority_sha256": "c" * 64,
            "attribution_mode": mode,
            "authenticated_workspace_identity_sha256": DIGESTS["workspace"],
            "authoritative_report_identity_sha256": DIGESTS["report"],
            "billing_authority_sha256": DIGESTS["billing"],
            "billing_method_sha256": DIGESTS["method"],
            "captured_at": "2026-08-27T17:00:30+00:00",
            "completeness_delay_seconds": 3600,
            "environment_scope_sha256": DIGESTS["environment"],
            "execution_manifest_sha256": None if execution_receipt is None else "d" * 64,
            "execution_receipt_sha256": execution_receipt,
            "execution_scope_sha256": DIGESTS["scope"],
            "filtered_report_sha256": hashlib.sha256(report).hexdigest(),
            "filtered_report_size_bytes": len(report),
            "identity_evidence_sha256": hashlib.sha256(identity).hexdigest(),
            "kind": ADDITIONAL_RECEIPT_KIND,
            "post_auth_receipt_sha256": hashlib.sha256(post).hexdigest(),
            "pre_auth_receipt_sha256": hashlib.sha256(pre).hexdigest(),
            "provider": "modal",
            "query_end": "2026-08-27T16:00:00+00:00",
            "query_start": "2026-08-27T14:00:00+00:00",
            "reservation_id": "additional-one",
            "schema_version": 1,
        }
    )
    return receipt, identity, report, pre, post


def _validate_additional(parts: tuple[bytes, bytes, bytes, bytes, bytes]):
    receipt, identity, report, pre, post = parts
    return validate_additional_settlement(
        receipt,
        identity,
        report,
        pre_auth_receipt_bytes=pre,
        post_auth_receipt_bytes=post,
        expected_reservation_id="additional-one",
        expected_execution_scope_sha256=DIGESTS["scope"],
        expected_additional_authority_sha256="c" * 64,
        expected_environment_scope_sha256=DIGESTS["environment"],
        expected_original_workspace_scope_sha256=DIGESTS["original"],
        expected_workspace_identity_sha256=DIGESTS["workspace"],
        expected_reconciliation_authority_sha256=DIGESTS["reconciliation"],
        expected_auth_binding_sha256=DIGESTS["binding"],
        expected_billing_authority_sha256=DIGESTS["billing"],
        expected_billing_method_sha256=DIGESTS["method"],
        expected_report_identity_sha256=DIGESTS["report"],
        action_consumed_at=datetime(2026, 8, 27, 14, 27, 54, tzinfo=UTC),
        latest_boundary_at=datetime(2026, 8, 27, 14, 29, 27, tzinfo=UTC),
        maximum_action_seconds=2700,
        expected_completeness_delay_seconds=3600,
        validated_at=datetime(2026, 8, 27, 17, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    "mode", ["call", "app", "billing_only", "workspace_zero_preidentity"]
)
def test_additional_settlement_accepts_each_factual_identity_mode(mode: str) -> None:
    evidence = _validate_additional(_additional_evidence(mode))
    assert evidence.attribution_mode == mode
    assert (evidence.provider_identity is None) == (mode == "workspace_zero_preidentity")


@pytest.mark.parametrize(
    "mutation", ["multiple", "nonzero_zero", "stale", "auth", "capture", "lineage"]
)
def test_additional_settlement_rejects_ambiguous_or_incomplete_evidence(mutation: str) -> None:
    receipt, identity, report, pre, post = _additional_evidence()
    raw_receipt = json.loads(receipt)
    raw_report = json.loads(report)
    if mutation == "multiple":
        raw_report["rows"].append({**raw_report["rows"][0], "object_id": "fc-" + "B" * 22})
    elif mutation == "nonzero_zero":
        receipt, identity, report, pre, post = _additional_evidence("workspace_zero_preidentity")
        raw_receipt, raw_report = json.loads(receipt), json.loads(report)
        raw_receipt["actual_cost_usd"] = "0.01"
    elif mutation == "stale":
        raw_receipt["query_end"] = "2026-08-27T15:00:00+00:00"
    elif mutation == "auth":
        post = pre
    elif mutation == "capture":
        raw_receipt["captured_at"] = "2026-08-27T16:59:59+00:00"
    else:
        raw_receipt["additional_authority_sha256"] = "e" * 64
    report = canonical_bytes(raw_report)
    raw_receipt["filtered_report_sha256"] = hashlib.sha256(report).hexdigest()
    raw_receipt["filtered_report_size_bytes"] = len(report)
    raw_receipt["post_auth_receipt_sha256"] = hashlib.sha256(post).hexdigest()
    receipt = canonical_bytes(raw_receipt)
    with pytest.raises(ReplacementSettlementError):
        _validate_additional((receipt, identity, report, pre, post))
