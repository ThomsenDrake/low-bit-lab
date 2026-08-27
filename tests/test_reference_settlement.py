from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from lowbit_lab.reference_settlement import (
    ReferenceSettlementError,
    validate_workspace_zero_settlement_evidence,
)

DIGESTS = {
    "recovery": "a" * 64,
    "workspace": "b" * 64,
    "authority": "c" * 64,
    "method": "d" * 64,
    "report_identity": "e" * 64,
    "scope": "f" * 64,
}
QUERY_START = datetime(2026, 8, 26, 23, 0, tzinfo=UTC)
QUERY_END = datetime(2026, 8, 27, 2, 0, tzinfo=UTC)
ACQUIRED_AT = datetime(2026, 8, 27, 3, 0, tzinfo=UTC)
LATEST_BOUNDARY = datetime(2026, 8, 26, 23, 41, 52, tzinfo=UTC)
REPORT = b"[]\n"
AUTH_METHOD = hashlib.sha256(
    b"modal-profile-current-before-and-after-with-local-digest-binding/v1"
).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _auth_receipt(*, authenticated_at: str, nonce: str) -> bytes:
    return _canonical(
        {
            "authenticated_at": authenticated_at,
            "binding_sha256": "1" * 64,
            "kind": "reference_modal_workspace_auth_receipt",
            "method_sha256": AUTH_METHOD,
            "provider": "modal",
            "schema_version": 1,
            "verification_nonce_sha256": nonce,
            "workspace_scope_sha256": DIGESTS["workspace"],
        }
    )


PRE_AUTH = _auth_receipt(authenticated_at="2026-08-27T02:59:00+00:00", nonce="4" * 64)
POST_AUTH = _auth_receipt(authenticated_at="2026-08-27T02:59:30+00:00", nonce="5" * 64)


def _receipt(**changes: object) -> bytes:
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "reference_workspace_zero_billing_evidence",
        "provider": "modal",
        "recovery_authority_sha256": DIGESTS["recovery"],
        "authenticated_workspace_scope_sha256": DIGESTS["workspace"],
        "auth_binding_sha256": "1" * 64,
        "pre_auth_receipt_sha256": hashlib.sha256(PRE_AUTH).hexdigest(),
        "post_auth_receipt_sha256": hashlib.sha256(POST_AUTH).hexdigest(),
        "billing_authority_sha256": DIGESTS["authority"],
        "billing_method_sha256": DIGESTS["method"],
        "authoritative_report_identity_sha256": DIGESTS["report_identity"],
        "reservation_id": "reservation-u8-auth-failure",
        "original_execution_scope_sha256": DIGESTS["scope"],
        "failure_code": "auth_before_provider_identity",
        "query_start": QUERY_START.isoformat(),
        "query_end": QUERY_END.isoformat(),
        "acquired_at": ACQUIRED_AT.isoformat(),
        "completeness_delay_seconds": 3600,
        "actual_cost_usd": "0",
        "currency": "USD",
        "report_sha256": hashlib.sha256(REPORT).hexdigest(),
        "report_size_bytes": len(REPORT),
        "row_count": 0,
        "pagination_complete": True,
        "filters": [],
        "all_environments": True,
        "all_resources": True,
    }
    receipt.update(changes)
    return _canonical(receipt)


def _validate(receipt: bytes | None = None, report: bytes = REPORT, **changes: object):
    arguments: dict[str, object] = {
        "pre_auth_receipt_bytes": PRE_AUTH,
        "post_auth_receipt_bytes": POST_AUTH,
        "expected_recovery_authority_sha256": DIGESTS["recovery"],
        "expected_workspace_scope_sha256": DIGESTS["workspace"],
        "expected_billing_authority_sha256": DIGESTS["authority"],
        "expected_billing_method_sha256": DIGESTS["method"],
        "expected_report_identity_sha256": DIGESTS["report_identity"],
        "expected_reservation_id": "reservation-u8-auth-failure",
        "expected_execution_scope_sha256": DIGESTS["scope"],
        "latest_durable_boundary": LATEST_BOUNDARY,
        "validated_at": ACQUIRED_AT,
        "maximum_action_seconds": 2700,
        "expected_completeness_delay_seconds": 3600,
    }
    arguments.update(changes)
    return validate_workspace_zero_settlement_evidence(
        _receipt() if receipt is None else receipt, report, **arguments
    )


def test_exact_empty_workspace_report_succeeds_and_returns_typed_lineage() -> None:
    result = _validate()
    assert result.actual_cost_usd == "0"
    assert result.row_count == 0
    assert result.report_sha256 == hashlib.sha256(REPORT).hexdigest()
    assert result.report_size_bytes == 3
    assert result.reservation_id == "reservation-u8-auth-failure"
    assert result.execution_scope_sha256 == DIGESTS["scope"]
    assert result.query_start == QUERY_START
    assert result.query_end == QUERY_END


@pytest.mark.parametrize(
    ("change", "message"),
    (
        ({"actual_cost_usd": "0.00"}, "exact zero"),
        ({"actual_cost_usd": "0.01"}, "exact zero"),
        ({"row_count": 1}, "empty"),
        ({"pagination_complete": False}, "pagination"),
        ({"filters": ["environment"]}, "unfiltered"),
        ({"all_environments": False}, "unfiltered"),
        ({"all_resources": False}, "unfiltered"),
        ({"failure_code": "auth_error"}, "failure code"),
        ({"currency": "usd"}, "currency"),
        ({"unknown": True}, "closed"),
    ),
)
def test_nonzero_rounded_filtered_partial_or_open_receipt_fails_closed(
    change: dict[str, object], message: str
) -> None:
    with pytest.raises(ReferenceSettlementError, match=message):
        _validate(_receipt(**change))


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("recovery_authority_sha256", "recovery"),
        ("authenticated_workspace_scope_sha256", "workspace"),
        ("billing_authority_sha256", "billing authority"),
        ("billing_method_sha256", "billing method"),
        (
            "authoritative_report_identity_sha256",
            "report identity",
        ),
        ("original_execution_scope_sha256", "execution scope"),
    ),
)
def test_wrong_authority_workspace_or_scope_binding_fails(
    field: str, message: str
) -> None:
    with pytest.raises(ReferenceSettlementError, match=message):
        _validate(_receipt(**{field: "9" * 64}))


def test_wrong_reservation_and_altered_report_bytes_fail() -> None:
    with pytest.raises(ReferenceSettlementError, match="reservation"):
        _validate(_receipt(reservation_id="another-reservation"))
    with pytest.raises(ReferenceSettlementError, match="report bytes"):
        _validate(report=b"[]")
    with pytest.raises(ReferenceSettlementError, match="canonical empty"):
        _validate(
            _receipt(
                report_sha256=hashlib.sha256(b"[]").hexdigest(),
                report_size_bytes=2,
            ),
            report=b"[]",
        )


def test_auth_receipt_bytes_are_revalidated_and_cross_bound() -> None:
    with pytest.raises(ReferenceSettlementError, match="pre-auth receipt bytes"):
        validate_workspace_zero_settlement_evidence(
            _receipt(),
            REPORT,
            pre_auth_receipt_bytes=PRE_AUTH + b" ",
            post_auth_receipt_bytes=POST_AUTH,
            expected_recovery_authority_sha256=DIGESTS["recovery"],
            expected_workspace_scope_sha256=DIGESTS["workspace"],
            expected_billing_authority_sha256=DIGESTS["authority"],
            expected_billing_method_sha256=DIGESTS["method"],
            expected_report_identity_sha256=DIGESTS["report_identity"],
            expected_reservation_id="reservation-u8-auth-failure",
            expected_execution_scope_sha256=DIGESTS["scope"],
            latest_durable_boundary=LATEST_BOUNDARY,
            validated_at=ACQUIRED_AT,
            maximum_action_seconds=2700,
            expected_completeness_delay_seconds=3600,
        )
    wrong_scope = json.loads(PRE_AUTH)
    wrong_scope["workspace_scope_sha256"] = "9" * 64
    wrong_scope_bytes = _canonical(wrong_scope)
    with pytest.raises(ReferenceSettlementError, match="workspace scope"):
        _validate(
            _receipt(pre_auth_receipt_sha256=hashlib.sha256(wrong_scope_bytes).hexdigest()),
            pre_auth_receipt_bytes=wrong_scope_bytes,
        )


def test_interval_must_be_exact_full_hour_complete_and_cover_action_window() -> None:
    with pytest.raises(ReferenceSettlementError, match="query interval"):
        _validate(_receipt(query_start=(QUERY_START + timedelta(seconds=1)).isoformat()))
    with pytest.raises(ReferenceSettlementError, match="action window"):
        _validate(_receipt(query_end=(QUERY_END - timedelta(hours=2)).isoformat()))
    with pytest.raises(ReferenceSettlementError, match="action window"):
        _validate(latest_durable_boundary=datetime(2026, 8, 27, 1, 30, tzinfo=UTC))


def test_acquisition_must_follow_completeness_delay_and_not_be_future() -> None:
    early = QUERY_END + timedelta(seconds=3599)
    with pytest.raises(ReferenceSettlementError, match="completeness delay"):
        _validate(_receipt(acquired_at=early.isoformat()))
    with pytest.raises(ReferenceSettlementError, match="future"):
        _validate(validated_at=ACQUIRED_AT - timedelta(seconds=1))
    with pytest.raises(ReferenceSettlementError, match="completeness delay"):
        _validate(_receipt(completeness_delay_seconds=1))


def test_receipt_bytes_must_be_canonical_and_timestamps_utc() -> None:
    indented = json.dumps(json.loads(_receipt()), indent=2).encode()
    with pytest.raises(ReferenceSettlementError, match="canonical"):
        _validate(indented)
    with pytest.raises(ReferenceSettlementError, match="UTC"):
        _validate(_receipt(acquired_at="2026-08-27T05:00:00+02:00"))
