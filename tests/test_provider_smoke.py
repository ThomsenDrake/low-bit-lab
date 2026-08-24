from __future__ import annotations

import inspect
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lowbit_lab.db import DatabaseError, ResultsDatabase
from lowbit_lab.modal_adapter import submit_provider_smoke
from lowbit_lab.provider_smoke import (
    ACTION_CAP_USD,
    SMOKE_RESOURCE_SHA256,
    ProviderSmokeCapability,
    ProviderSmokeError,
    _validate_live_lineage,
    approval_wording,
    build_contract,
    execute,
    main,
    validate_approval,
    validate_contract,
)

TEST_NOW = datetime.now(UTC)


def _contract(
    *,
    ledger_sha256: str = "a" * 64,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
):
    return build_contract(
        config_sha256="1" * 64,
        challenge_sha256="2" * 64,
        reviewed_commit_sha256="4" * 40,
        control_plane_sha256="5" * 64,
        environment_scope_sha256="6" * 64,
        provider_environment="low-bit-lab",
        resource_envelope_sha256=SMOKE_RESOURCE_SHA256,
        formula_approval_sha256="8" * 64,
        billing_authority_sha256="b" * 64,
        authoritative_report_identity_sha256="c" * 64,
        billing_completeness_delay_seconds=3600,
        budget_authority_plan_sha256="9" * 64,
        ledger_sha256=ledger_sha256,
        approval_issued_at=(issued_at or TEST_NOW - timedelta(minutes=5)).isoformat(),
        approval_expires_at=(expires_at or TEST_NOW + timedelta(minutes=25)).isoformat(),
    )


def _approval(contract):
    import hashlib

    return {
        "schema_version": 1,
        "kind": "modal_provider_smoke_approval",
        "action_contract_sha256": contract.action_contract_sha256,
        "statement_sha256": hashlib.sha256(approval_wording(contract).encode()).hexdigest(),
        "challenge_sha256": contract.challenge_sha256,
        "execution_scope_sha256": contract.execution_scope_sha256,
        "provider_environment": contract.provider_environment,
        "reviewed_commit_sha256": contract.reviewed_commit_sha256,
        "environment_scope_sha256": contract.environment_scope_sha256,
        "maximum_cost_usd": ACTION_CAP_USD,
        "expires_at": contract.approval_expires_at,
        "weights_authorized": False,
        "u8_authorized": False,
    }


def test_contract_is_closed_and_binds_every_field() -> None:
    contract = _contract()
    assert validate_contract(asdict(contract)) == contract
    changed = asdict(contract)
    changed["maximum_cost_usd"] = "3.99"
    with pytest.raises(ProviderSmokeError, match="boundary changed"):
        validate_contract(changed)
    changed = asdict(contract)
    changed["model"] = "forbidden"
    with pytest.raises(ProviderSmokeError, match="closed"):
        validate_contract(changed)


def test_approval_is_exact_expiring_and_scope_bound() -> None:
    contract = _contract()
    approval = _approval(contract)
    now = TEST_NOW
    assert len(validate_approval(approval, contract, now=now)) == 64
    approval["execution_scope_sha256"] = "b" * 64
    with pytest.raises(ProviderSmokeError, match="does not match"):
        validate_approval(approval, contract, now=now)
    approval = _approval(contract)
    with pytest.raises(ProviderSmokeError, match="expired"):
        validate_approval(approval, contract, now=now + timedelta(days=2))
    future_contract = _contract(
        issued_at=now + timedelta(minutes=1),
        expires_at=now + timedelta(minutes=20),
    )
    with pytest.raises(ProviderSmokeError, match="not yet valid"):
        validate_approval(_approval(future_contract), future_contract, now=now)


def test_adapter_has_no_model_or_payload_surface_and_fails_before_modal_import(
    tmp_path: Path,
) -> None:
    assert set(inspect.signature(submit_provider_smoke).parameters) == {"capability"}
    before = sys.modules.get("modal")
    with pytest.raises(ProviderSmokeError, match="verify|capability"):
        submit_provider_smoke(
            ProviderSmokeCapability(
                db_path=tmp_path / "missing.sqlite",
                action_contract_sha256="1" * 64,
                execution_scope_sha256="2" * 64,
                reservation_id="reservation",
                owner_id="owner",
                provider_environment="low-bit-lab",
            )
        )
    assert sys.modules.get("modal") is before


def test_smoke_reservation_is_atomic_exact_and_replay_safe(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    contract = _contract()
    arguments = {
        "reservation_id": "reservation-1",
        "action_contract_sha256": contract.action_contract_sha256,
        "execution_scope_sha256": contract.execution_scope_sha256,
        "challenge_sha256": contract.challenge_sha256,
        "approval_json": json.dumps(_approval(contract), sort_keys=True, separators=(",", ":")),
        "contract_json": json.dumps(asdict(contract), sort_keys=True, separators=(",", ":")),
        "owner_id": "owner-1",
        "occurred_at": "2026-08-23T12:00:00+00:00",
    }
    database.reserve_provider_smoke(**arguments)
    with pytest.raises(DatabaseError, match="ledger|consumed"):
        database.reserve_provider_smoke(**arguments)
    with database.connect_readonly() as connection:
        row = connection.execute(
            "SELECT status, requested_cost_usd FROM provider_smoke_reservations"
        ).fetchone()
    assert tuple(row) == ("reserved", "4.00")


def test_ambiguous_provider_start_is_audit_blocked(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    contract = _contract()
    database.reserve_provider_smoke(
        reservation_id="reservation-1",
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        challenge_sha256=contract.challenge_sha256,
        approval_json=json.dumps(_approval(contract), sort_keys=True, separators=(",", ":")),
        contract_json=json.dumps(asdict(contract), sort_keys=True, separators=(",", ":")),
        owner_id="owner-1",
        occurred_at="2026-08-23T12:00:00+00:00",
    )
    database.mark_provider_smoke_submission_pending(
        "reservation-1", owner_id="owner-1", occurred_at="2026-08-23T12:01:00+00:00"
    )
    database.mark_provider_smoke_audit_blocked(
        "reservation-1",
        owner_id="owner-1",
        reason="unknown provider state",
        occurred_at="2026-08-23T12:02:00+00:00",
    )
    with database.connect_readonly() as connection:
        row = connection.execute(
            "SELECT status, provider_call_id, failure_reason FROM provider_smoke_reservations"
        ).fetchone()
    assert tuple(row) == ("audit_blocked", None, "unknown provider state")


def test_submission_capability_is_one_shot(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    contract = _contract()
    database.reserve_provider_smoke(
        reservation_id="reservation-1",
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        challenge_sha256=contract.challenge_sha256,
        approval_json=json.dumps(_approval(contract), sort_keys=True, separators=(",", ":")),
        contract_json=json.dumps(asdict(contract), sort_keys=True, separators=(",", ":")),
        owner_id="owner-1",
        occurred_at="2026-08-23T12:00:00+00:00",
    )
    database.mark_provider_smoke_submission_pending(
        "reservation-1", owner_id="owner-1", occurred_at="2026-08-23T12:01:00+00:00"
    )
    claim = {
        "reservation_id": "reservation-1",
        "owner_id": "owner-1",
        "action_contract_sha256": contract.action_contract_sha256,
        "execution_scope_sha256": contract.execution_scope_sha256,
        "provider_environment": contract.provider_environment,
        "occurred_at": "2026-08-23T12:02:00+00:00",
    }
    database.claim_provider_smoke_submission(**claim)
    with pytest.raises(DatabaseError, match="consumed"):
        database.claim_provider_smoke_submission(**claim)


def test_real_modal_sdk_constructs_adapter_without_provider_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    modal = pytest.importorskip("modal")
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    contract = _contract()
    database.reserve_provider_smoke(
        reservation_id="reservation-sdk",
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        challenge_sha256=contract.challenge_sha256,
        approval_json=json.dumps(_approval(contract), sort_keys=True, separators=(",", ":")),
        contract_json=json.dumps(asdict(contract), sort_keys=True, separators=(",", ":")),
        owner_id="owner-sdk",
        occurred_at="2026-08-23T12:00:00+00:00",
    )
    database.mark_provider_smoke_submission_pending(
        "reservation-sdk", owner_id="owner-sdk", occurred_at="2026-08-23T12:01:00+00:00"
    )

    class StopBeforeProvider(Exception):
        pass

    def stop_before_provider(*args, **kwargs):
        raise StopBeforeProvider

    monkeypatch.setattr(modal.App, "run", stop_before_provider)
    with pytest.raises(StopBeforeProvider):
        submit_provider_smoke(
            ProviderSmokeCapability(
                db_path=database.path,
                action_contract_sha256=contract.action_contract_sha256,
                execution_scope_sha256=contract.execution_scope_sha256,
                reservation_id="reservation-sdk",
                owner_id="owner-sdk",
                provider_environment="low-bit-lab",
            )
        )


def test_plan_is_read_only_and_never_imports_modal(tmp_path: Path, capsys) -> None:
    contract = _contract()
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(asdict(contract)), encoding="utf-8")
    modal_before = sys.modules.get("modal")
    assert main(["plan", "--contract", str(contract_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["provider_contacted"] is False
    assert output["paid_action_ready"] is False
    assert output["execution_scope_sha256"] == contract.execution_scope_sha256
    assert sys.modules.get("modal") is modal_before
    assert list(tmp_path.iterdir()) == [contract_path]


def test_execute_with_fake_boundary_consumes_one_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    (tmp_path / "configs/local").mkdir(parents=True)
    (tmp_path / "results/local").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    ledger_path = tmp_path / "configs/local/reference-budget.json"
    ledger_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "reference_budget_authority",
                "approved_plan_sha256": "9" * 64,
                "currency": "USD",
                "phase": 1,
                "phase_cap_usd": "4.00",
                "total_cap_usd": "4.00",
                "single_job_cap_usd": "4.00",
                "a100_80gb_price_per_second_usd": "0.0005",
                "cpu_core_price_per_second_usd": "0.00001",
                "memory_gib_price_per_second_usd": "0.000001",
                "submission_authorized": True,
            }
        ),
        encoding="utf-8",
    )
    contract = _contract(ledger_sha256=hashlib.sha256(ledger_path.read_bytes()).hexdigest())
    approval_path = tmp_path / "configs/local/provider-smoke-approval.json"
    approval_path.write_text(json.dumps(_approval(contract)), encoding="utf-8")
    database_path = Path("results/local/reference.sqlite")
    calls = 0

    def fake_submit(capability: ProviderSmokeCapability):
        nonlocal calls
        calls += 1
        database = ResultsDatabase(capability.db_path)
        database.claim_provider_smoke_submission(
            reservation_id=capability.reservation_id,
            owner_id=capability.owner_id,
            action_contract_sha256=capability.action_contract_sha256,
            execution_scope_sha256=capability.execution_scope_sha256,
            provider_environment=capability.provider_environment,
            occurred_at="2026-08-23T12:00:30+00:00",
        )
        database.mark_provider_smoke_submitted(
            capability.reservation_id,
            owner_id=capability.owner_id,
            provider_call_id="fake-call",
            occurred_at="2026-08-23T12:01:00+00:00",
        )
        observation = {"schema_version": 1}
        database.mark_provider_smoke_observed(
            capability.reservation_id,
            owner_id=capability.owner_id,
            observation_json=json.dumps(observation, sort_keys=True, separators=(",", ":")),
            observation_sha256=hashlib.sha256(
                json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            occurred_at="2026-08-23T12:02:00+00:00",
        )
        return {"provider_call_id": "fake-call", "observation": observation}

    monkeypatch.setattr("lowbit_lab.modal_adapter.submit_provider_smoke", fake_submit)
    monkeypatch.setattr("lowbit_lab.provider_smoke._validate_live_lineage", lambda *a, **k: None)
    result = execute(
        contract,
        Path("configs/local/provider-smoke-approval.json"),
        database_path,
        Path("configs/local/reference-budget.json"),
        tmp_path,
        Path("configs/local/reference.yaml"),
    )
    assert calls == 1
    assert result["result"]["provider_call_id"] == "fake-call"
    assert not (outside / database_path).exists()
    with ResultsDatabase(tmp_path / database_path).connect_readonly() as connection:
        row = connection.execute(
            "SELECT status, requested_cost_usd FROM provider_smoke_reservations"
        ).fetchone()
    assert tuple(row) == ("settlement_pending", "4.00")


def test_live_lineage_accepts_exact_state_and_rejects_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    contract = _contract()
    config = SimpleNamespace(
        sha256=contract.config_sha256,
        challenge_sha256=contract.challenge_sha256,
        inputs={
            "reviewed_commit_sha256": contract.reviewed_commit_sha256,
            "control_plane_sha256": contract.control_plane_sha256,
        },
        provider={
            "environment_scope_sha256": contract.environment_scope_sha256,
            "billing_authority_sha256": contract.billing_authority_sha256,
            "authoritative_report_identity_sha256": (contract.authoritative_report_identity_sha256),
        },
        gates={"formula_approval_sha256": contract.formula_approval_sha256},
    )
    runtime = {
        "git_dirty": False,
        "git_commit": contract.reviewed_commit_sha256,
        "control_plane_sha256": contract.control_plane_sha256,
    }
    monkeypatch.setattr("lowbit_lab.modal_job.load_reference_job_config", lambda *a, **k: config)
    monkeypatch.setattr("lowbit_lab.runtime.runtime_metadata", lambda *a, **k: runtime)
    _validate_live_lineage(
        contract, root=tmp_path, config_path=Path("configs/local/reference.yaml")
    )
    config.sha256 = "f" * 64
    with pytest.raises(ProviderSmokeError, match="lineage"):
        _validate_live_lineage(
            contract, root=tmp_path, config_path=Path("configs/local/reference.yaml")
        )
    config.sha256 = contract.config_sha256
    runtime["git_commit"] = "0" * 40
    with pytest.raises(ProviderSmokeError, match="runtime"):
        _validate_live_lineage(
            contract, root=tmp_path, config_path=Path("configs/local/reference.yaml")
        )
    runtime["git_commit"] = contract.reviewed_commit_sha256
    runtime["control_plane_sha256"] = "e" * 64
    with pytest.raises(ProviderSmokeError, match="runtime"):
        _validate_live_lineage(
            contract, root=tmp_path, config_path=Path("configs/local/reference.yaml")
        )


def _settlement_ready_database(path: Path) -> tuple[ResultsDatabase, object]:
    import hashlib

    database = ResultsDatabase(path)
    database.initialize()
    contract = _contract()
    contract_json = json.dumps(asdict(contract), sort_keys=True, separators=(",", ":"))
    database.reserve_provider_smoke(
        reservation_id="reservation-settlement",
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        challenge_sha256=contract.challenge_sha256,
        approval_json=json.dumps(_approval(contract), sort_keys=True, separators=(",", ":")),
        contract_json=contract_json,
        owner_id="owner-settlement",
        occurred_at="2026-08-23T12:00:00+00:00",
    )
    database.mark_provider_smoke_submission_pending(
        "reservation-settlement",
        owner_id="owner-settlement",
        occurred_at="2026-08-23T12:01:00+00:00",
    )
    database.claim_provider_smoke_submission(
        reservation_id="reservation-settlement",
        owner_id="owner-settlement",
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        provider_environment=contract.provider_environment,
        occurred_at="2026-08-23T12:02:00+00:00",
    )
    database.mark_provider_smoke_submitted(
        "reservation-settlement",
        owner_id="owner-settlement",
        provider_call_id="provider-call-1",
        occurred_at="2026-08-23T12:03:00+00:00",
    )
    observation = json.dumps({"schema_version": 1}, separators=(",", ":"))
    database.mark_provider_smoke_observed(
        "reservation-settlement",
        owner_id="owner-settlement",
        observation_json=observation,
        observation_sha256=hashlib.sha256(observation.encode()).hexdigest(),
        occurred_at=(TEST_NOW - timedelta(hours=2)).isoformat(),
    )
    return database, contract


def _billing_report(contract, *, authority: str | None = None, cost: str = "3.75") -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "kind": "provider_billing_report_receipt",
            "provider_job_id": "provider-call-1",
            "billing_authority_sha256": authority or contract.billing_authority_sha256,
            "authoritative_report_identity_sha256": (contract.authoritative_report_identity_sha256),
            "covered_through": TEST_NOW.isoformat(),
            "actual_cost_usd": cost,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_provider_smoke_settlement_requires_complete_authoritative_billing(
    tmp_path: Path, capsys
) -> None:
    import hashlib

    root = tmp_path
    database, contract = _settlement_ready_database(root / "results/local/reference.sqlite")

    report = _billing_report(contract)
    report_sha256 = hashlib.sha256(report.encode()).hexdigest()
    with pytest.raises(DatabaseError, match="authority"):
        database.settle_provider_smoke(
            "reservation-settlement",
            billing_report_json=report,
            billing_report_sha256=report_sha256,
            occurred_at=(TEST_NOW - timedelta(hours=1, minutes=30)).isoformat(),
        )
    mismatched = _billing_report(contract, authority="d" * 64)
    with pytest.raises(DatabaseError, match="authority"):
        database.settle_provider_smoke(
            "reservation-settlement",
            billing_report_json=mismatched,
            billing_report_sha256=hashlib.sha256(mismatched.encode()).hexdigest(),
            occurred_at=TEST_NOW.isoformat(),
        )
    report_path = root / "reports/local/provider-smoke-billing.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(report, encoding="utf-8")
    assert (
        main(
            [
                "settle",
                "--root",
                str(root),
                "--db",
                "results/local/reference.sqlite",
                "--report",
                "reports/local/provider-smoke-billing.json",
                "--reservation-id",
                "reservation-settlement",
            ]
        )
        == 0
    )
    settlement = json.loads(capsys.readouterr().out)
    assert settlement == {
        "command": "settle",
        "ok": True,
        "provider_actual_cost_usd": "3.75",
        "provider_contacted": False,
        "status": "settled",
    }
    with pytest.raises(DatabaseError, match="cannot settle"):
        database.settle_provider_smoke(
            "reservation-settlement",
            billing_report_json=report,
            billing_report_sha256=report_sha256,
            occurred_at=TEST_NOW.isoformat(),
        )
    with database.connect_readonly() as connection:
        row = connection.execute(
            "SELECT status, provider_actual_cost_usd, settlement_identity "
            "FROM provider_smoke_reservations"
        ).fetchone()
    assert tuple(row) == ("settled", "3.75", report_sha256)


def test_provider_smoke_over_cap_settlement_fails_closed(tmp_path: Path) -> None:
    import hashlib

    database, contract = _settlement_ready_database(tmp_path / "over-cap.sqlite")
    report = _billing_report(contract, cost="4.01")
    settlement = database.settle_provider_smoke(
        "reservation-settlement",
        billing_report_json=report,
        billing_report_sha256=hashlib.sha256(report.encode()).hexdigest(),
        occurred_at=TEST_NOW.isoformat(),
    )
    assert settlement == {"status": "failed", "provider_actual_cost_usd": "4.01"}
    with database.connect_readonly() as connection:
        row = connection.execute(
            "SELECT status, provider_actual_cost_usd, failure_reason "
            "FROM provider_smoke_reservations"
        ).fetchone()
    assert tuple(row) == (
        "failed",
        "4.01",
        "provider_actual_cost_exceeded_local_reservation",
    )


def test_provider_smoke_settlement_rejects_symlinked_results_escape(tmp_path: Path, capsys) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (tmp_path / "results").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not available")
    assert (
        main(
            [
                "settle",
                "--root",
                str(tmp_path),
                "--db",
                "results/local/reference.sqlite",
                "--report",
                "reports/local/provider-smoke-billing.json",
                "--reservation-id",
                "reservation",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().err)
    assert "outside repository" in error["error"]
    assert not (outside / "local/reference.sqlite").exists()
