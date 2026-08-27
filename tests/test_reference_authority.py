import hashlib
import json
from pathlib import Path

import pytest

import lowbit_lab.reference_authority as reference_authority
from lowbit_lab.constants import REFERENCE_RECOVERY_AUTHORITY_SHA256
from lowbit_lab.handoff import canonical_json, sha256_json
from lowbit_lab.reference_authority import (
    ACTION_CLASSES,
    BOOTSTRAP_AUTHORITY_PATH,
    BOOTSTRAP_STATEMENT_PATH,
    RECOVERY_AUTHORITY_PATH,
    RECOVERY_STATEMENT_PATH,
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
    SIGNED_CDN_AUTHORITY_PATH,
    SIGNED_CDN_STATEMENT_PATH,
    WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
    WORKSPACE_RECONCILIATION_STATEMENT_PATH,
    ReferenceAuthorityError,
    authorize_reference_action,
    authorize_reference_bootstrap_action,
    build_reference_recovery_authority,
    build_workspace_scope_reconciliation_authority,
    validate_reference_authority,
    validate_reference_bootstrap_authority,
    validate_reference_recovery_authority,
    validate_reference_signed_cdn_authority,
    validate_workspace_scope_reconciliation_authority,
)


def _copy_authority_inputs(root: Path) -> Path:
    repository = Path(__file__).resolve().parents[1]
    for relative in (
        "configs/local/reference-authority-statement.txt",
        "configs/local/reference-campaign-authority.json",
        "docs/plans/local/2026-08-21-2358-feat-full-weight-baseline-plan.md",
        "docs/plans/local/2026-08-22-1126-feat-provider-constraint-amendment-plan.md",
        "docs/plans/local/2026-08-23-provider-observation-trust-override-plan.md",
        "docs/plans/local/2026-08-25-1200-feat-autonomous-reference-baseline-plan.md",
    ):
        source = repository / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    return root / "configs/local/reference-campaign-authority.json"


def _copy_bootstrap_authority_inputs(root: Path) -> Path:
    _copy_authority_inputs(root)
    repository = Path(__file__).resolve().parents[1]
    for relative in (BOOTSTRAP_STATEMENT_PATH, BOOTSTRAP_AUTHORITY_PATH):
        source = repository / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    return root / BOOTSTRAP_AUTHORITY_PATH


def _copy_signed_cdn_authority_inputs(root: Path) -> Path:
    _copy_bootstrap_authority_inputs(root)
    repository = Path(__file__).resolve().parents[1]
    for relative in (SIGNED_CDN_STATEMENT_PATH, SIGNED_CDN_AUTHORITY_PATH):
        source = repository / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    return root / SIGNED_CDN_AUTHORITY_PATH


def _copy_recovery_authority_inputs(root: Path) -> Path:
    _copy_signed_cdn_authority_inputs(root)
    repository = Path(__file__).resolve().parents[1]
    statement = root / RECOVERY_STATEMENT_PATH
    statement.parent.mkdir(parents=True, exist_ok=True)
    statement.write_bytes((repository / RECOVERY_STATEMENT_PATH).read_bytes())
    authority = root / RECOVERY_AUTHORITY_PATH
    authority.write_bytes(
        (canonical_json(build_reference_recovery_authority()) + "\n").encode("utf-8")
    )
    return authority


def _write_reconciliation_authority(
    root: Path, monkeypatch: pytest.MonkeyPatch, *, equal_identities: bool = False
) -> Path:
    _copy_recovery_authority_inputs(root)
    statement = b"synthetic workspace reconciliation authority\n"
    monkeypatch.setattr(
        reference_authority,
        "REFERENCE_WORKSPACE_RECONCILIATION_STATEMENT_SHA256",
        hashlib.sha256(statement).hexdigest(),
    )
    statement_path = root / WORKSPACE_RECONCILIATION_STATEMENT_PATH
    statement_path.parent.mkdir(parents=True, exist_ok=True)
    statement_path.write_bytes(statement)
    original = "1" * 64
    authority = build_workspace_scope_reconciliation_authority(
        original_workspace_scope_sha256=original,
        authenticated_workspace_identity_sha256=(original if equal_identities else "2" * 64),
        original_reservation_id="reservation-test",
        original_execution_scope_sha256="3" * 64,
        billing_authority_sha256="4" * 64,
    )
    monkeypatch.setattr(
        reference_authority,
        "REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256",
        sha256_json(authority),
    )
    authority_path = root / WORKSPACE_RECONCILIATION_AUTHORITY_PATH
    authority_path.parent.mkdir(parents=True, exist_ok=True)
    authority_path.write_bytes((canonical_json(authority) + "\n").encode())
    return authority_path


def test_workspace_reconciliation_validates_real_canonical_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority_path = _write_reconciliation_authority(tmp_path, monkeypatch)
    validated = validate_workspace_scope_reconciliation_authority(tmp_path, authority_path)
    assert validated["original_workspace_scope_sha256"] == "1" * 64
    assert validated["authenticated_workspace_identity_sha256"] == "2" * 64


def test_workspace_reconciliation_rejects_equal_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority_path = _write_reconciliation_authority(
        tmp_path, monkeypatch, equal_identities=True
    )
    with pytest.raises(ReferenceAuthorityError, match="distinct identities"):
        validate_workspace_scope_reconciliation_authority(tmp_path, authority_path)


def test_exact_authority_accepts_all_closed_action_classes(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    assert validate_reference_authority(tmp_path, authority_path) == REFERENCE_AUTHORITY_SHA256
    digests = {
        authorize_reference_action(tmp_path, authority_path, action) for action in ACTION_CLASSES
    }
    assert len(digests) == len(ACTION_CLASSES)
    assert authorize_reference_action(
        tmp_path, authority_path, "zero_spend_prepare"
    ) == authorize_reference_action(tmp_path, authority_path, "zero_spend_prepare")


def test_reconciliation_and_proposal_remain_authorized_after_u8_contact(
    tmp_path: Path,
) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    assert authorize_reference_action(tmp_path, authority_path, "billing_reconcile")
    assert authorize_reference_action(tmp_path, authority_path, "u9_compile_proposal")


def test_statement_bytes_are_exact_and_drift_fails(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    statement = tmp_path / "configs/local/reference-authority-statement.txt"
    assert not statement.read_bytes().startswith(b"\xef\xbb\xbf")
    assert not statement.read_bytes().endswith((b"\n", b"\r"))
    statement.write_bytes(statement.read_bytes() + b"\n")
    with pytest.raises(ReferenceAuthorityError, match="statement"):
        validate_reference_authority(tmp_path, authority_path)


def test_controlling_plan_byte_drift_fails(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    plan = tmp_path / "docs/plans/local/2026-08-25-1200-feat-autonomous-reference-baseline-plan.md"
    plan.write_bytes(plan.read_bytes() + b"drift")
    with pytest.raises(ReferenceAuthorityError, match="plan"):
        validate_reference_authority(tmp_path, authority_path)


def test_authority_requires_exact_canonical_raw_json_bytes(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority_path.write_text(json.dumps(authority, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ReferenceAuthorityError, match="raw bytes"):
        validate_reference_authority(tmp_path, authority_path)


def test_authority_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    raw = authority_path.read_text(encoding="utf-8")
    authority_path.write_text(
        raw.replace('{"action_classes":', '{"schema_version":1,"action_classes":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ReferenceAuthorityError, match="duplicate keys"):
        validate_reference_authority(tmp_path, authority_path)


def test_authority_read_error_does_not_disclose_machine_path(tmp_path: Path) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    (tmp_path / "configs/local/reference-authority-statement.txt").unlink()
    with pytest.raises(ReferenceAuthorityError) as caught:
        validate_reference_authority(tmp_path, authority_path)
    assert str(tmp_path) not in str(caught.value)
    assert str(caught.value) == "cannot read reference authority statement"


@pytest.mark.parametrize(
    ("field", "value"),
    (("timeout_seconds", 2701), ("action_classes", ["zero_spend_prepare"])),
)
def test_authority_resource_and_action_drift_fail(
    tmp_path: Path, field: str, value: object
) -> None:
    authority_path = _copy_authority_inputs(tmp_path)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority[field] = value
    authority_path.write_text(json.dumps(authority), encoding="utf-8")
    with pytest.raises(ReferenceAuthorityError, match="authority"):
        validate_reference_authority(tmp_path, authority_path)

    authority_path = _copy_authority_inputs(tmp_path)
    with pytest.raises(ReferenceAuthorityError, match="action class"):
        authorize_reference_action(tmp_path, authority_path, "u8_reference_retry")


def test_exact_bootstrap_amendment_is_separate_and_narrow(tmp_path: Path) -> None:
    authority_path = _copy_bootstrap_authority_inputs(tmp_path)
    assert (
        validate_reference_bootstrap_authority(tmp_path, authority_path)
        == REFERENCE_BOOTSTRAP_AUTHORITY_SHA256
    )
    assert authorize_reference_bootstrap_action(tmp_path, authority_path, "u8_reference_once")
    with pytest.raises(ReferenceAuthorityError, match="bootstrap action class"):
        authorize_reference_bootstrap_action(tmp_path, authority_path, "zero_spend_prepare")


@pytest.mark.parametrize("suffix", (b"\n", b"\r\n"))
def test_bootstrap_statement_newline_drift_fails(tmp_path: Path, suffix: bytes) -> None:
    authority_path = _copy_bootstrap_authority_inputs(tmp_path)
    statement = tmp_path / BOOTSTRAP_STATEMENT_PATH
    statement.write_bytes(statement.read_bytes() + suffix)
    with pytest.raises(ReferenceAuthorityError, match="bootstrap authority statement"):
        validate_reference_bootstrap_authority(tmp_path, authority_path)


def test_bootstrap_statement_bom_drift_fails(tmp_path: Path) -> None:
    authority_path = _copy_bootstrap_authority_inputs(tmp_path)
    statement = tmp_path / BOOTSTRAP_STATEMENT_PATH
    statement.write_bytes(b"\xef\xbb\xbf" + statement.read_bytes())
    with pytest.raises(ReferenceAuthorityError, match="bootstrap authority statement"):
        validate_reference_bootstrap_authority(tmp_path, authority_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("merge_commit", "0" * 40),
        ("action_class", "u8_reference_retry"),
        ("timeout_seconds", 2699),
        ("ephemeral_disk_mib", 1),
        ("gpu", "A100-40GB:1"),
        ("configured_context_tokens", 131072),
        ("empirical_provider_facts_may_be_bootstrapped", []),
    ),
)
def test_bootstrap_authority_drift_fails(tmp_path: Path, field: str, value: object) -> None:
    authority_path = _copy_bootstrap_authority_inputs(tmp_path)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority[field] = value
    authority_path.write_text(
        json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ReferenceAuthorityError, match="bootstrap authority"):
        validate_reference_bootstrap_authority(tmp_path, authority_path)


def test_bootstrap_requires_unchanged_parent_authority(tmp_path: Path) -> None:
    authority_path = _copy_bootstrap_authority_inputs(tmp_path)
    parent = tmp_path / "configs/local/reference-campaign-authority.json"
    parent.write_bytes(parent.read_bytes().replace(b'"u8_slots":1', b'"u8_slots":2'))
    with pytest.raises(ReferenceAuthorityError, match="reference authority"):
        validate_reference_bootstrap_authority(tmp_path, authority_path)


def test_exact_signed_cdn_amendment_is_separate_and_narrow(tmp_path: Path) -> None:
    authority_path = _copy_signed_cdn_authority_inputs(tmp_path)
    assert (
        validate_reference_signed_cdn_authority(tmp_path, authority_path)
        == REFERENCE_SIGNED_CDN_AUTHORITY_SHA256
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_redirects", 6),
        ("additional_provider_actions_authorized", True),
        ("retries_authorized", True),
        ("signed_redirect_policy", []),
    ),
)
def test_signed_cdn_authority_drift_fails(
    tmp_path: Path, field: str, value: object
) -> None:
    authority_path = _copy_signed_cdn_authority_inputs(tmp_path)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority[field] = value
    authority_path.write_text(
        json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ReferenceAuthorityError, match="signed CDN authority"):
        validate_reference_signed_cdn_authority(tmp_path, authority_path)


def test_exact_recovery_authority_is_separate_narrow_and_statement_bound(
    tmp_path: Path,
) -> None:
    authority_path = _copy_recovery_authority_inputs(tmp_path)
    assert (
        validate_reference_recovery_authority(tmp_path, authority_path)
        == REFERENCE_RECOVERY_AUTHORITY_SHA256
    )
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    assert authority["original_u8_slot_remains_consumed"] is True
    assert authority["replacement_u8_slots"] == 1
    assert authority["replacement_retry_slots"] == 0
    assert authority["action_classes"] == [
        "zero_spend_phase1",
        "preidentity_zero_settlement",
        "u8_reference_replacement_once",
    ]
    assert authority["settlement_actual_cost_usd"] == "0"
    assert authority["configured_context_tokens"] == 262144
    assert authority["proven_useful_context_tokens"] is None

    statement = tmp_path / RECOVERY_STATEMENT_PATH
    assert hashlib.sha256(statement.read_bytes()).hexdigest() == authority["statement_sha256"]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("replacement_u8_slots", 2),
        ("replacement_retry_slots", 1),
        ("incremental_u8_cap_usd", "4.01"),
        ("failure_code", "generic_auth_error"),
        ("settlement_actual_cost_usd", "0.00"),
        ("private_data_authorized", True),
    ),
)
def test_recovery_authority_rejects_semantic_or_byte_drift(
    tmp_path: Path, field: str, value: object
) -> None:
    authority_path = _copy_recovery_authority_inputs(tmp_path)
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority[field] = value
    authority_path.write_text(
        json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ReferenceAuthorityError, match="recovery authority"):
        validate_reference_recovery_authority(tmp_path, authority_path)


def test_recovery_authority_requires_unchanged_parent_and_exact_statement(
    tmp_path: Path,
) -> None:
    authority_path = _copy_recovery_authority_inputs(tmp_path)
    (tmp_path / RECOVERY_STATEMENT_PATH).write_bytes(
        (tmp_path / RECOVERY_STATEMENT_PATH).read_bytes() + b"\n"
    )
    with pytest.raises(ReferenceAuthorityError, match="recovery authority statement"):
        validate_reference_recovery_authority(tmp_path, authority_path)

    authority_path = _copy_recovery_authority_inputs(tmp_path)
    parent = tmp_path / SIGNED_CDN_AUTHORITY_PATH
    parent.write_bytes(parent.read_bytes().replace(b'"max_redirects":5', b'"max_redirects":4'))
    with pytest.raises(ReferenceAuthorityError, match="signed CDN authority"):
        validate_reference_recovery_authority(tmp_path, authority_path)
