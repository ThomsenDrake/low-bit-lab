from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from lowbit_lab import controller
from lowbit_lab.controller import (
    ALLOWED_ACTIONS,
    CONTROLLER_PLAN_PATH,
    FORBIDDEN_ACTIONS,
    FORMULA_APPROVAL_STATEMENT_SHA256,
    REVIEWED_FORMULA_SHA256,
    STANDING_STATEMENT_SHA256,
    ControllerError,
    ControllerInputs,
    controller_prepare,
    controller_verify,
    validate_formula_approval,
    validate_standing_authority,
)
from lowbit_lab.db import ResultsDatabase
from lowbit_lab.handoff import build_pre_spend_handoff


def _write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def test_standing_authority_is_closed_and_cannot_broaden_actions(tmp_path: Path) -> None:
    plan = tmp_path / CONTROLLER_PLAN_PATH
    plan.parent.mkdir(parents=True)
    plan.write_text("approved plan\n", encoding="utf-8")
    receipt = {
        "schema_version": 1,
        "kind": "zero_spend_standing_authority",
        "statement_sha256": STANDING_STATEMENT_SHA256,
        "controlling_plan_path": CONTROLLER_PLAN_PATH,
        "controlling_plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "allowed_actions": list(ALLOWED_ACTIONS),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "scope": "zero_spend_preparation",
        "expires_at": None,
        "human_origin": "attested",
    }
    path = tmp_path / "configs/local/standing.json"
    expected = _write_json(path, receipt)
    assert validate_standing_authority(tmp_path, path) == (
        expected,
        receipt["controlling_plan_sha256"],
    )

    receipt["allowed_actions"].append("submit")
    _write_json(path, receipt)
    with pytest.raises(ControllerError, match="action set changed"):
        validate_standing_authority(tmp_path, path)


def test_standing_authority_rejects_oversized_control_artifact(tmp_path: Path) -> None:
    path = tmp_path / "configs/local/standing.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b" " * (controller.MAX_CONTROL_ARTIFACT_BYTES + 1))
    with pytest.raises(ControllerError, match="exceeds byte limit"):
        validate_standing_authority(tmp_path, path)


def test_formula_receipt_binds_both_formula_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    formula_path = tmp_path / "reports/local/formula.json"
    formula_path.parent.mkdir(parents=True)
    formula_path.write_bytes(b"approved formula bytes")
    actual = hashlib.sha256(formula_path.read_bytes()).hexdigest()
    monkeypatch.setattr(controller, "APPROVED_FORMULA_SHA256", actual)
    config = SimpleNamespace(
        gates={
            "formula_authority_path": "reports/local/formula.json",
            "formula_approval_path": "reports/local/formula-approval.json",
            "formula_approval_sha256": "0" * 64,
        },
        inputs={"formula_authority_sha256": actual},
    )
    receipt = {
        "schema_version": 1,
        "kind": "formula_approval_receipt",
        "statement_sha256": FORMULA_APPROVAL_STATEMENT_SHA256,
        "reviewed_formula_sha256": REVIEWED_FORMULA_SHA256,
        "approved_formula_sha256": actual,
        "formula_authority_path": "reports/local/formula.json",
        "human_origin": "attested",
    }
    path = tmp_path / "reports/local/formula-approval.json"
    receipt_sha = _write_json(path, receipt)
    config.gates["formula_approval_sha256"] = receipt_sha
    assert validate_formula_approval(tmp_path, path, config) == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    receipt["reviewed_formula_sha256"] = "0" * 64
    _write_json(path, receipt)
    with pytest.raises(ControllerError, match="formula approval lineage mismatch"):
        validate_formula_approval(tmp_path, path, config)


def _prepared() -> ControllerInputs:
    preview = {
        "submit": False,
        "weights_transferred": False,
        "actual_cost_usd": "0",
        "challenge_sha256": "1" * 64,
        "config_sha256": "2" * 64,
        "reference_execution_scope_sha256": "3" * 64,
        "blockers": ["memory_fit_unproven", "cold_path_time_budget_unproven"],
    }
    config = SimpleNamespace(
        inputs={
            "reviewed_commit_sha256": "4" * 40,
            "control_plane_sha256": "5" * 64,
        }
    )
    handoff = build_pre_spend_handoff(
        preview=preview,
        reviewed_commit_sha256="4" * 40,
        control_plane_sha256="5" * 64,
        standing_authority_sha256="6" * 64,
        formula_approval_sha256="7" * 64,
        controller_context_sha256="8" * 64,
        configured_context_tokens=262144,
    )
    return ControllerInputs(
        config=config,
        standing_authority_sha256="6" * 64,
        formula_approval_sha256="7" * 64,
        context_sha256="8" * 64,
        handoff=handoff,
    )


def test_prepare_and_verify_commit_only_zero_spend_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: _prepared())
    db = tmp_path / "results/local/controller.sqlite"
    result = controller_prepare(
        root=tmp_path,
        config_path=Path("configs/local/reference.yaml"),
        db_path=db,
        authority_path=Path("configs/local/standing.json"),
        formula_approval_path=Path("reports/local/formula-approval.json"),
        output_dir=Path("reports/local/controller"),
    )
    assert result["state"] == "paid_decision_required"
    assert result["handoff"]["budget"]["actual_cost_usd"] == "0"
    assert (tmp_path / result["artifact_path"]).is_file()

    verified = controller_verify(
        root=tmp_path,
        config_path=Path("configs/local/reference.yaml"),
        db_path=db,
        authority_path=Path("configs/local/standing.json"),
        formula_approval_path=Path("reports/local/formula-approval.json"),
    )
    assert verified["mutated"] is False
    assert verified["artifact_sha256"] == result["artifact_sha256"]


def test_verify_detects_context_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prepared = _prepared()
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: prepared)
    db = tmp_path / "results/local/controller.sqlite"
    controller_prepare(
        root=tmp_path,
        config_path=Path("unused"),
        db_path=db,
        authority_path=Path("unused"),
        formula_approval_path=Path("unused"),
        output_dir=Path("reports/local/controller"),
    )
    drifted = _prepared()
    object.__setattr__(drifted, "context_sha256", "9" * 64)
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: drifted)
    with pytest.raises(ControllerError, match="context drift"):
        controller_verify(
            root=tmp_path,
            config_path=Path("unused"),
            db_path=db,
            authority_path=Path("unused"),
            formula_approval_path=Path("unused"),
        )


def test_verify_missing_database_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: _prepared())
    db = tmp_path / "results/local/missing.sqlite"
    with pytest.raises(ControllerError, match="database does not exist"):
        controller_verify(
            root=tmp_path,
            config_path=Path("unused"),
            db_path=db,
            authority_path=Path("unused"),
            formula_approval_path=Path("unused"),
        )
    assert not db.exists()


def test_verify_rejects_noncanonical_artifact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: _prepared())
    db = tmp_path / "results/local/controller.sqlite"
    result = controller_prepare(
        root=tmp_path,
        config_path=Path("unused"),
        db_path=db,
        authority_path=Path("unused"),
        formula_approval_path=Path("unused"),
        output_dir=Path("reports/local/controller"),
    )
    artifact = tmp_path / result["artifact_path"]
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    with pytest.raises(ControllerError, match="committed handoff drift"):
        controller_verify(
            root=tmp_path,
            config_path=Path("unused"),
            db_path=db,
            authority_path=Path("unused"),
            formula_approval_path=Path("unused"),
        )


def test_prepare_terminalizes_post_acquisition_output_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "prepare_inputs", lambda **_: _prepared())
    db_path = tmp_path / "results/local/controller.sqlite"
    with pytest.raises(ControllerError, match="reports/local"):
        controller_prepare(
            root=tmp_path,
            config_path=Path("unused"),
            db_path=db_path,
            authority_path=Path("unused"),
            formula_approval_path=Path("unused"),
            output_dir=Path("artifacts/local/not-allowed"),
        )
    workspace_id = hashlib.sha256(tmp_path.resolve().as_posix().encode()).hexdigest()
    cycle = ResultsDatabase(db_path).get_latest_controller_cycle(workspace_id)
    assert cycle is not None
    assert cycle["state"] == "failed"
