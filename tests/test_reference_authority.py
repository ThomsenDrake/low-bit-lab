import json
from pathlib import Path

import pytest

from lowbit_lab.reference_authority import (
    ACTION_CLASSES,
    BOOTSTRAP_AUTHORITY_PATH,
    BOOTSTRAP_STATEMENT_PATH,
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    ReferenceAuthorityError,
    authorize_reference_action,
    authorize_reference_bootstrap_action,
    validate_reference_authority,
    validate_reference_bootstrap_authority,
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
