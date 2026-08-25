import json
from pathlib import Path

import pytest

from lowbit_lab.db import ResultsDatabase
from lowbit_lab.reference_authority import (
    ACTION_CLASSES,
    REFERENCE_AUTHORITY_SHA256,
    ReferenceAuthorityError,
    authorize_reference_action,
    validate_reference_authority,
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
    database = ResultsDatabase(tmp_path / "reference.sqlite")
    database.initialize()
    database.consume_reference_u8_slot(
        REFERENCE_AUTHORITY_SHA256,
        execution_scope_sha256="a" * 64,
        occurred_at="2026-08-25T12:00:00+00:00",
    )
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "consumed"
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
