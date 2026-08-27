import ast
import hashlib
import json
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import lowbit_lab.modal_job as modal_job
from lowbit_lab import reference_gates
from lowbit_lab.modal_job import (
    ReferenceJobError,
    load_reference_job_config,
    main,
    plan_reference_bootstrap_preview,
    plan_reference_dry_run,
    plan_reference_preview,
    redact_provider_output,
    validate_reference_approval,
)
from lowbit_lab.reference_contract import (
    APPROVED_PROVIDER_AMENDMENT_SHA256,
    APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
    APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256,
    ORIGINAL_APPROVED_PLAN_SHA256,
)
from lowbit_lab.reference_gates import A100_80GB_BYTES, MEMORY_FORMULA, TIME_FORMULA

ORIGINAL_PLAN_PATH = "docs/plans/local/2026-08-21-2358-feat-full-weight-baseline-plan.md"
AMENDMENT_PATH = "docs/plans/local/2026-08-22-1126-feat-provider-constraint-amendment-plan.md"
TRUST_OVERRIDE_PLAN_PATH = "docs/plans/local/2026-08-23-provider-observation-trust-override-plan.md"


def test_runtime_authority_binds_verified_exact_receipt_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt_bytes = b'{\n  "schema_version": 1\n}\n'
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt_bytes)
    observed: list[object] = []
    monkeypatch.setattr(
        modal_job,
        "verify_current_installed_environment",
        lambda receipt, root, lock: observed.append(receipt) or {"verified": True},
    )
    expected = hashlib.sha256(receipt_bytes).hexdigest()

    assert modal_job._verify_runtime_receipt_bytes(
        receipt_path,
        root=tmp_path,
        runtime_lock=SimpleNamespace(),
        expected_sha256=expected,
    )
    assert observed == [{"schema_version": 1}]
    assert not modal_job._verify_runtime_receipt_bytes(
        receipt_path,
        root=tmp_path,
        runtime_lock=SimpleNamespace(),
        expected_sha256="0" * 64,
    )


def test_evaluation_authority_binds_noncanonical_persisted_bytes(tmp_path: Path) -> None:
    content = b'{\n  "schema_version": 1\n}\n'
    path = tmp_path / "evaluation.json"
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    raw = modal_job._load_bound_evaluation_lock(path, expected_file_sha256=digest)

    assert raw == {"schema_version": 1}
    with pytest.raises(ReferenceJobError, match="evaluation lock bytes drift"):
        modal_job._load_bound_evaluation_lock(path, expected_file_sha256="0" * 64)


def _budget(path: Path, plan_sha256: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "reference_budget_authority",
                "approved_plan_sha256": plan_sha256,
                "currency": "USD",
                "phase": 1,
                "phase_cap_usd": "4.00",
                "total_cap_usd": "4.00",
                "single_job_cap_usd": "4.00",
                "a100_80gb_price_per_second_usd": "0.000694",
                "cpu_core_price_per_second_usd": "0.0000131",
                "memory_gib_price_per_second_usd": "0.00000222",
                "submission_authorized": False,
            }
        ),
        encoding="utf-8",
    )


def _config(tmp_path: Path, **changes: object) -> Path:
    configs = tmp_path / "configs" / "local"
    configs.mkdir(parents=True, exist_ok=True)
    plans = tmp_path / "docs" / "plans" / "local"
    plans.mkdir(parents=True, exist_ok=True)
    repository_plans = Path(__file__).resolve().parents[1] / "docs" / "plans" / "local"
    for name in (
        Path(ORIGINAL_PLAN_PATH).name,
        Path(AMENDMENT_PATH).name,
        Path(TRUST_OVERRIDE_PLAN_PATH).name,
    ):
        (plans / name).write_bytes((repository_plans / name).read_bytes())
    _budget(configs / "reference-budget.json", ORIGINAL_APPROVED_PLAN_SHA256)
    raw = {
        "schema_version": 5,
        "kind": "modal_reference_preview",
        "experiment_id": "reference-preview-v1",
        "original_approved_plan_path": ORIGINAL_PLAN_PATH,
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "approved_amendment_path": AMENDMENT_PATH,
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "approved_trust_override_plan_path": TRUST_OVERRIDE_PLAN_PATH,
        "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
        "budget_policy_path": "configs/local/reference-budget.json",
        "inputs": {
            "source_revision": "d" * 40,
            "weight_inventory_sha256": "1" * 64,
            "weight_inventory_tensor_bytes": 55,
            "provenance_manifest_sha256": "2" * 64,
            "runtime_receipt_sha256": "3" * 64,
            "evaluation_lock_sha256": "4" * 64,
            "evaluation_max_context_tokens": 32768,
            "formula_authority_sha256": None,
            "reviewed_commit_sha256": "a" * 40,
            "control_plane_sha256": "5" * 64,
        },
        "authority_files": {
            "weight_inventory_path": None,
            "source_shard_metadata_path": None,
            "provenance_manifest_path": None,
            "runtime_lock_path": None,
            "runtime_receipt_path": None,
            "evaluation_lock_path": None,
            "evaluation_fixture_root": None,
        },
        "resources": {
            "gpu_type": "A100-80GB",
            "gpu_count": 1,
            "cpu_cores": 8,
            "memory_gib": 96,
            "ephemeral_disk_gib": 512,
            "timeout_seconds": 2700,
            "startup_timeout_seconds": None,
            "retries": 0,
        },
        "provider": {
            "submit": False,
            "scheduling_enabled": False,
            "cloud_upload": False,
            "mounts": [],
            "volumes": [],
            "secrets": [],
            "credentials_source": "provider_local",
            "workspace_scope_sha256": "8" * 64,
            "environment_scope_sha256": "9" * 64,
            "constraint_contract_path": None,
            "constraint_contract_sha256": None,
            "observation_receipt_path": None,
            "observation_receipt_sha256": None,
            "observation_screenshot_sha256": "b" * 64,
            "trust_override_path": None,
            "trust_override_sha256": None,
            "human_approval_statement_sha256": None,
            "billing_authority_path": None,
            "billing_authority_sha256": None,
            "authoritative_report_identity_sha256": "1" * 64,
            "billing_completeness_delay_seconds": 3600,
        },
        "gates": {
            "formula_authority_path": None,
            "formula_approval_path": None,
            "formula_approval_sha256": None,
            "memory_fit_evidence_path": None,
            "memory_fit_evidence_sha256": None,
            "cold_path_time_evidence_path": None,
            "cold_path_time_evidence_sha256": None,
            "memory_method_path": None,
            "memory_method_sha256": None,
            "cold_path_method_path": None,
            "cold_path_method_sha256": None,
            "architecture_metadata_path": None,
            "architecture_metadata_sha256": None,
            "image_build_identity_path": None,
            "image_build_identity_sha256": None,
            "bound_receipt_root": None,
        },
        "approval_artifact_path": None,
    }
    raw.update(changes)
    path = configs / "reference.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def test_reference_preview_is_exact_non_submitting_and_zero_actual(tmp_path: Path) -> None:
    config = load_reference_job_config(_config(tmp_path), root=tmp_path)
    preview = plan_reference_preview(config, root=tmp_path)
    assert preview["schema_version"] == 3
    assert preview["submit"] is False
    assert preview["actual_cost_usd"] == "0"
    assert preview["local_reservation_limit_usd"] == "4.00"
    assert "maximum_cost_usd" not in preview
    assert preview["estimated_cost_usd"] == "2.73218400"
    assert preview["resources"] == {
        "gpu_type": "A100-80GB",
        "gpu_count": 1,
        "cpu_cores": 8,
        "memory_gib": 96,
        "ephemeral_disk_gib": 512,
        "timeout_seconds": 2700,
        "startup_timeout_seconds": None,
        "retries": 0,
    }
    assert "formula_authority_missing" in preview["blockers"]
    assert "provider_concurrency_unproven" in preview["blockers"]
    assert "provider_residual_cost_risk_unaccepted" in preview["blockers"]
    assert "provider_billing_scope_unproven" in preview["blockers"]
    assert "execution_approval_missing" in preview["blockers"]
    assert len(preview["challenge_sha256"]) == 64


def test_reference_source_revision_is_closed_and_immutable(tmp_path: Path) -> None:
    config = load_reference_job_config(_config(tmp_path), root=tmp_path)
    assert config.inputs["source_revision"] == "d" * 40
    raw = yaml.safe_load(_config(tmp_path).read_text(encoding="utf-8"))
    raw["inputs"]["source_revision"] = "D" * 40
    path = tmp_path / "configs" / "local" / "bad-revision.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="source_revision"):
        load_reference_job_config(path, root=tmp_path)


def test_reference_preview_requires_independent_formula_approval_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _config(tmp_path)
    reports = tmp_path / "reports/local"
    reports.mkdir(parents=True)
    formula = reports / "formula.json"
    formula.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "reference_formula_authority",
                "authority_id": "reference-resource-accounting",
                "authority_version": "1.0.0",
                "memory_formula": MEMORY_FORMULA,
                "time_formula": TIME_FORMULA,
                "maximum_gpu_memory_bytes": A100_80GB_BYTES,
                "maximum_context_tokens": 32768,
                "timeout_seconds": 2700,
                "approval_status": "approved",
            }
        ),
        encoding="utf-8",
    )
    formula_sha = hashlib.sha256(formula.read_bytes()).hexdigest()
    monkeypatch.setattr(reference_gates, "APPROVED_FORMULA_SHA256", formula_sha)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["inputs"]["formula_authority_sha256"] = formula_sha
    raw["gates"]["formula_authority_path"] = "reports/local/formula.json"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    config = load_reference_job_config(path, root=tmp_path)
    assert (
        "formula_approval_receipt_unverified"
        in plan_reference_preview(config, root=tmp_path)["blockers"]
    )

    receipt = reports / "formula-approval.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "formula_approval_receipt",
                "statement_sha256": reference_gates.FORMULA_APPROVAL_STATEMENT_SHA256,
                "reviewed_formula_sha256": reference_gates.REVIEWED_FORMULA_SHA256,
                "approved_formula_sha256": formula_sha,
                "formula_authority_path": "reports/local/formula.json",
                "human_origin": "attested",
            }
        ),
        encoding="utf-8",
    )
    raw["gates"]["formula_approval_path"] = "reports/local/formula-approval.json"
    raw["gates"]["formula_approval_sha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_reference_job_config(path, root=tmp_path)
    assert (
        "formula_approval_receipt_unverified"
        not in plan_reference_preview(config, root=tmp_path)["blockers"]
    )


def test_reference_config_rejects_legacy_schema_version(tmp_path: Path) -> None:
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["schema_version"] = 1
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="unsupported"):
        load_reference_job_config(path, root=tmp_path)


def test_reference_preview_derives_gates_from_hashed_evidence(tmp_path: Path) -> None:
    path = _config(tmp_path)
    reports = tmp_path / "reports" / "local"
    reports.mkdir(parents=True)
    formula = reports / "formula.json"
    formula.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "reference_formula_authority",
                "authority_id": "reference-resource-accounting",
                "authority_version": "1.0.0",
                "memory_formula": MEMORY_FORMULA,
                "time_formula": TIME_FORMULA,
                "maximum_gpu_memory_bytes": A100_80GB_BYTES,
                "maximum_context_tokens": 32768,
                "timeout_seconds": 2700,
                "approval_status": "pending_human_review",
            }
        ),
        encoding="utf-8",
    )
    formula_sha256 = hashlib.sha256(formula.read_bytes()).hexdigest()
    memory = reports / "memory.json"
    memory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "memory_fit_evidence",
                "inventory_sha256": "1" * 64,
                "evaluation_lock_sha256": "4" * 64,
                "maximum_context_tokens": 32768,
                "tensor_bytes": 55,
                "runtime_overhead_bytes": 10,
                "kv_cache_bytes": 20,
                "allocator_reserve_bytes": 5,
                "usable_gpu_memory_bytes": 90,
                "method_sha256": formula_sha256,
            }
        ),
        encoding="utf-8",
    )
    timing = reports / "time.json"
    timing.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "cold_path_time_evidence",
                "evaluation_lock_sha256": "4" * 64,
                "timeout_seconds": 2700,
                "transfer_seconds": 1200,
                "verification_seconds": 300,
                "load_seconds": 400,
                "evaluation_seconds": 600,
                "safety_margin_seconds": 200,
                "method_sha256": formula_sha256,
            }
        ),
        encoding="utf-8",
    )
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["inputs"]["formula_authority_sha256"] = formula_sha256
    raw["gates"] = {
        "formula_authority_path": "reports/local/formula.json",
        "formula_approval_path": None,
        "formula_approval_sha256": None,
        "memory_fit_evidence_path": "reports/local/memory.json",
        "memory_fit_evidence_sha256": hashlib.sha256(memory.read_bytes()).hexdigest(),
        "cold_path_time_evidence_path": "reports/local/time.json",
        "cold_path_time_evidence_sha256": hashlib.sha256(timing.read_bytes()).hexdigest(),
        "memory_method_path": None,
        "memory_method_sha256": None,
        "cold_path_method_path": None,
        "cold_path_method_sha256": None,
        "architecture_metadata_path": None,
        "architecture_metadata_sha256": None,
        "image_build_identity_path": None,
        "image_build_identity_sha256": None,
        "bound_receipt_root": None,
    }
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="schema-v2 reproducibility"):
        load_reference_job_config(path, root=tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gpu_type", "A100"),
        ("gpu_count", 2),
        ("cpu_cores", 7),
        ("memory_gib", 95),
        ("ephemeral_disk_gib", 89),
        ("timeout_seconds", 2701),
        ("startup_timeout_seconds", 1),
        ("retries", 1),
    ],
)
def test_reference_resource_drift_fails_closed(tmp_path: Path, field: str, value: object) -> None:
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["resources"][field] = value
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="resource envelope"):
        load_reference_job_config(path, root=tmp_path)


def test_reference_config_rejects_credentials_and_submission(tmp_path: Path) -> None:
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"]["api_token"] = "do-not-store"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="credential-like"):
        load_reference_job_config(path, root=tmp_path)

    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["experiment_id"] = "ghp_" + "a" * 24
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="credential-shaped value"):
        load_reference_job_config(path, root=tmp_path)

    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"]["submit"] = True
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="submission remains disabled"):
        load_reference_job_config(path, root=tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("approved_amendment_path", None, "approved_amendment_path"),
        ("approved_amendment_path", ORIGINAL_PLAN_PATH, "approved amendment path"),
        ("approved_amendment_sha256", "f" * 64, "approved amendment"),
    ],
)
def test_reference_config_rejects_absent_or_wrong_amendment(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw[field] = value
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match=message):
        load_reference_job_config(path, root=tmp_path)


def _write_provider_evidence(tmp_path: Path, *, observed_at: datetime) -> dict[str, str]:
    reports = tmp_path / "reports" / "local"
    reports.mkdir(parents=True, exist_ok=True)
    constraint = {
        "schema_version": 2,
        "kind": "provider_constraint_contract",
        "provider": "modal",
        "workspace_scope_sha256": "8" * 64,
        "environment_scope_sha256": "9" * 64,
        "maximum_concurrent_containers": 1,
        "maximum_concurrent_gpus": 1,
        "provider_hard_budget_available": False,
        "provider_crash_rescheduling_bounded": False,
        "observation_method_sha256": "a" * 64,
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
    }
    constraint_path = reports / "constraint.json"
    constraint_path.write_text(json.dumps(constraint), encoding="utf-8")
    constraint_sha = hashlib.sha256(constraint_path.read_bytes()).hexdigest()
    receipt = {
        "schema_version": 2,
        "kind": "provider_constraint_observation_receipt",
        "provider": "modal",
        "workspace_scope_sha256": "8" * 64,
        "environment_scope_sha256": "9" * 64,
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "constraint_contract_sha256": constraint_sha,
        "screenshot_sha256": "b" * 64,
        "observed_maximum_concurrent_containers": 1,
        "observed_maximum_concurrent_gpus": 1,
        "active_containers": 0,
        "active_gpus": 0,
        "observed_at": observed_at.isoformat(),
    }
    receipt_path = reports / "observation.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    billing = {
        "schema_version": 2,
        "kind": "provider_billing_authority_contract",
        "provider": "modal",
        "environment_scope_sha256": "9" * 64,
        "attribution_method_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "d" * 64,
        "billing_completeness_delay_seconds": 3600,
    }
    billing_path = reports / "billing.json"
    billing_path.write_text(json.dumps(billing), encoding="utf-8")
    return {
        "constraint_contract_path": "reports/local/constraint.json",
        "constraint_contract_sha256": constraint_sha,
        "observation_receipt_path": "reports/local/observation.json",
        "observation_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "billing_authority_path": "reports/local/billing.json",
        "billing_authority_sha256": hashlib.sha256(billing_path.read_bytes()).hexdigest(),
        "authoritative_report_identity_sha256": "d" * 64,
        "billing_completeness_delay_seconds": 3600,
    }


def test_reference_preview_verifies_fresh_provider_evidence_and_rejects_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"].update(
        _write_provider_evidence(tmp_path, observed_at=validated_at - timedelta(minutes=15))
    )
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr("lowbit_lab.modal_job._now_datetime", lambda: validated_at)
    config = load_reference_job_config(path, root=tmp_path)
    blockers = plan_reference_preview(config, root=tmp_path)["blockers"]
    assert "provider_concurrency_unproven" not in blockers
    assert "provider_billing_scope_unproven" not in blockers

    raw["provider"]["environment_scope_sha256"] = "e" * 64
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    drifted = load_reference_job_config(path, root=tmp_path)
    assert drifted.challenge_sha256 != config.challenge_sha256
    blockers = plan_reference_preview(drifted, root=tmp_path)["blockers"]
    assert "provider_concurrency_unproven" in blockers
    assert "provider_billing_scope_unproven" in blockers


def test_reference_preview_rejects_observation_older_than_fifteen_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"].update(
        _write_provider_evidence(
            tmp_path, observed_at=validated_at - timedelta(minutes=15, seconds=1)
        )
    )
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr("lowbit_lab.modal_job._now_datetime", lambda: validated_at)
    blockers = plan_reference_preview(
        load_reference_job_config(path, root=tmp_path), root=tmp_path
    )["blockers"]
    assert "provider_concurrency_unproven" in blockers


def test_reference_preview_accepts_bound_human_trust_override_for_stale_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated_at = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"].update(
        _write_provider_evidence(tmp_path, observed_at=validated_at - timedelta(days=1))
    )
    statement_sha = APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256
    override = {
        "schema_version": 1,
        "kind": "provider_observation_trust_override",
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "approved_provider_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
        "constraint_contract_sha256": raw["provider"]["constraint_contract_sha256"],
        "observation_receipt_sha256": raw["provider"]["observation_receipt_sha256"],
        "screenshot_sha256": raw["provider"]["observation_screenshot_sha256"],
        "workspace_scope_sha256": raw["provider"]["workspace_scope_sha256"],
        "environment_scope_sha256": raw["provider"]["environment_scope_sha256"],
        "human_approval_statement_sha256": statement_sha,
        "human_approved": True,
        "observation_is_stale": True,
        "configuration_drift_risk_accepted": True,
        "provider_residual_cost_risk_accepted": True,
        "provider_hard_budget_available": False,
    }
    override_path = tmp_path / "reports" / "local" / "trust-override.json"
    override_path.write_text(json.dumps(override), encoding="utf-8")
    raw["provider"].update(
        {
            "trust_override_path": "reports/local/trust-override.json",
            "trust_override_sha256": hashlib.sha256(override_path.read_bytes()).hexdigest(),
            "human_approval_statement_sha256": statement_sha,
        }
    )
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr("lowbit_lab.modal_job._now_datetime", lambda: validated_at)

    preview = plan_reference_preview(load_reference_job_config(path, root=tmp_path), root=tmp_path)
    assert preview["provider_constraint_authority"] == "human_trust_override"
    assert "provider_concurrency_unproven" not in preview["blockers"]
    assert "provider_residual_cost_risk_unaccepted" not in preview["blockers"]
    assert "execution_approval_missing" in preview["blockers"]

    constraint_path = tmp_path / "reports" / "local" / "constraint.json"
    constraint_bytes = constraint_path.read_bytes()
    constraint_path.write_text("{}", encoding="utf-8")
    blocked = plan_reference_preview(load_reference_job_config(path, root=tmp_path), root=tmp_path)
    assert blocked["provider_constraint_authority"] == "unproven"
    assert "provider_concurrency_unproven" in blocked["blockers"]
    constraint_path.write_bytes(constraint_bytes)

    override["configuration_drift_risk_accepted"] = False
    override_path.write_text(json.dumps(override), encoding="utf-8")
    raw["provider"]["trust_override_sha256"] = hashlib.sha256(
        override_path.read_bytes()
    ).hexdigest()
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    blocked = plan_reference_preview(load_reference_job_config(path, root=tmp_path), root=tmp_path)
    assert blocked["provider_constraint_authority"] == "unproven"
    assert "provider_concurrency_unproven" in blocked["blockers"]


def test_reference_preview_clears_each_provider_blocker_with_bound_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    path = _config(tmp_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["provider"].update(
        _write_provider_evidence(tmp_path, observed_at=validated_at - timedelta(minutes=1))
    )
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_reference_job_config(path, root=tmp_path)
    approval = tmp_path / "configs" / "local" / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "kind": "reference_execution_approval",
                "challenge_sha256": config.challenge_sha256,
                "reviewed_commit_sha256": "a" * 40,
                "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
                "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
                "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
                "constraint_contract_sha256": raw["provider"]["constraint_contract_sha256"],
                "observation_receipt_sha256": raw["provider"]["observation_receipt_sha256"],
                "billing_authority_sha256": raw["provider"]["billing_authority_sha256"],
                "workspace_scope_sha256": raw["provider"]["workspace_scope_sha256"],
                "environment_scope_sha256": raw["provider"]["environment_scope_sha256"],
                "authoritative_report_identity_sha256": raw["provider"][
                    "authoritative_report_identity_sha256"
                ],
                "billing_completeness_delay_seconds": raw["provider"][
                    "billing_completeness_delay_seconds"
                ],
                "trust_override_sha256": None,
                "provider_residual_cost_risk_accepted": True,
                "local_reservation_limit_usd": "4.00",
                "expires_at": "2026-08-22T12:30:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    raw["approval_artifact_path"] = "configs/local/approval.json"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr("lowbit_lab.modal_job._now_datetime", lambda: validated_at)

    blockers = plan_reference_preview(
        load_reference_job_config(path, root=tmp_path), root=tmp_path
    )["blockers"]
    for blocker in (
        "provider_concurrency_unproven",
        "provider_residual_cost_risk_unaccepted",
        "provider_billing_scope_unproven",
    ):
        assert blocker not in blockers

    observation_path = tmp_path / "reports" / "local" / "observation.json"
    observation_bytes = observation_path.read_bytes()
    observation_path.write_text("{}", encoding="utf-8")
    blockers = plan_reference_preview(
        load_reference_job_config(path, root=tmp_path), root=tmp_path
    )["blockers"]
    assert "provider_concurrency_unproven" in blockers
    assert "provider_billing_scope_unproven" not in blockers
    assert "provider_residual_cost_risk_unaccepted" not in blockers
    observation_path.write_bytes(observation_bytes)

    billing_path = tmp_path / "reports" / "local" / "billing.json"
    billing_bytes = billing_path.read_bytes()
    billing_path.write_text("{}", encoding="utf-8")
    blockers = plan_reference_preview(
        load_reference_job_config(path, root=tmp_path), root=tmp_path
    )["blockers"]
    assert "provider_concurrency_unproven" not in blockers
    assert "provider_billing_scope_unproven" in blockers
    assert "provider_residual_cost_risk_unaccepted" not in blockers
    billing_path.write_bytes(billing_bytes)

    changed = json.loads(approval.read_text(encoding="utf-8"))
    changed["provider_residual_cost_risk_accepted"] = False
    approval.write_text(json.dumps(changed), encoding="utf-8")
    blockers = plan_reference_preview(
        load_reference_job_config(path, root=tmp_path), root=tmp_path
    )["blockers"]
    assert "provider_residual_cost_risk_unaccepted" in blockers
    assert "provider_concurrency_unproven" not in blockers
    assert "provider_billing_scope_unproven" not in blockers


def test_bootstrap_preview_filters_only_empirical_precontact_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_reference_job_config(_config(tmp_path), root=tmp_path)
    request_bytes = b"request"
    image_bytes = b"image"
    (tmp_path / "request.json").write_bytes(request_bytes)
    (tmp_path / "image.json").write_bytes(image_bytes)
    request = SimpleNamespace(
        canonical_json=json.dumps(
            {"provider_capability": {"receipt_sha256": "c" * 64}},
            sort_keys=True,
            separators=(",", ":"),
        ),
        sha256="a" * 64,
    )
    image = SimpleNamespace(sha256="b" * 64, recipe_sha256="d" * 64)
    base = {
        "blockers": [
            "memory_fit_unproven",
            "cold_path_time_budget_unproven",
            "execution_approval_missing",
        ]
    }
    monkeypatch.setattr("lowbit_lab.modal_job.plan_reference_preview", lambda *_a, **_k: base)
    monkeypatch.setattr(
        "lowbit_lab.modal_job.validate_bootstrap_request_bytes", lambda _value: request
    )
    monkeypatch.setattr("lowbit_lab.modal_job.validate_image_lock_bytes", lambda _value: image)
    monkeypatch.setattr("lowbit_lab.modal_job.validate_request_image_lock", lambda *_a: None)
    monkeypatch.setattr("lowbit_lab.modal_job.validate_reference_authority", lambda *_a: "x")
    monkeypatch.setattr(
        "lowbit_lab.modal_job.validate_reference_bootstrap_authority", lambda *_a: "y"
    )
    monkeypatch.setattr(
        "lowbit_lab.modal_job._verify_reference_authorities",
        lambda *_a, **_k: True,
    )
    monkeypatch.setattr(
        "lowbit_lab.modal_job.validate_provider_capability_receipt", lambda *_a, **_k: {}
    )
    monkeypatch.setattr(
        "lowbit_lab.modal_job.load_manifest",
        lambda *_a: SimpleNamespace(public_remote="public", private_values=()),
    )
    monkeypatch.setattr(
        "lowbit_lab.modal_job.scan_publication",
        lambda *_a, **_k: {"ok": True},
    )
    result = plan_reference_bootstrap_preview(
        config,
        root=tmp_path,
        request_path=Path("request.json"),
        request_sha256=hashlib.sha256(request_bytes).hexdigest(),
        image_lock_path=Path("image.json"),
        image_lock_sha256=hashlib.sha256(image_bytes).hexdigest(),
        provider_capability_path=Path("capability.json"),
        provider_capability_sha256="c" * 64,
        billing_authority_path=Path("billing-authority.json"),
        billing_receipt_path=Path("billing-receipt.json"),
        billing_report_path=Path("billing-report.json"),
        publication_manifest_path=Path("publication.yaml"),
    )
    assert result["bootstrap_ready"] is True
    assert result["blockers"] == []
    assert result["configured_context_tokens"] == 262144
    assert result["proven_useful_context_tokens"] is None

    base["blockers"] = ["review_tree_dirty", "memory_fit_unproven"]
    stopped = plan_reference_bootstrap_preview(
        config,
        root=tmp_path,
        request_path=Path("request.json"),
        request_sha256=hashlib.sha256(request_bytes).hexdigest(),
        image_lock_path=Path("image.json"),
        image_lock_sha256=hashlib.sha256(image_bytes).hexdigest(),
        provider_capability_path=Path("capability.json"),
        provider_capability_sha256="c" * 64,
        billing_authority_path=Path("billing-authority.json"),
        billing_receipt_path=Path("billing-receipt.json"),
        billing_report_path=Path("billing-report.json"),
        publication_manifest_path=Path("publication.yaml"),
    )
    assert stopped["bootstrap_ready"] is False
    assert stopped["blockers"] == ["review_tree_dirty"]


def test_provider_output_is_bounded_and_redacted() -> None:
    output = redact_provider_output(
        "modal_token_id="
        + "identifier "
        + "modal_token_secret:"
        + "supersecret "
        + "api_key="
        + "anothersecret "
        + '{"password":"'
        + 'json-secret"} '
        + "Authorization: Bearer "
        + "bearer-secret "
        + "x" * 5000
    )
    assert "identifier" not in output
    assert "supersecret" not in output
    assert "anothersecret" not in output
    assert "json-secret" not in output
    assert "bearer-secret" not in output
    assert len(output) <= 4096


def test_reference_approval_is_separate_bound_and_expiring(tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "kind": "reference_execution_approval",
                "challenge_sha256": "a" * 64,
                "reviewed_commit_sha256": "b" * 40,
                "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
                "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
                "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
                "constraint_contract_sha256": "c" * 64,
                "observation_receipt_sha256": "d" * 64,
                "billing_authority_sha256": "e" * 64,
                "workspace_scope_sha256": "8" * 64,
                "environment_scope_sha256": "9" * 64,
                "authoritative_report_identity_sha256": "1" * 64,
                "billing_completeness_delay_seconds": 3600,
                "trust_override_sha256": None,
                "provider_residual_cost_risk_accepted": True,
                "local_reservation_limit_usd": "4.00",
                "expires_at": "2026-08-22T01:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    result = validate_reference_approval(
        approval,
        expected_challenge_sha256="a" * 64,
        expected_original_plan_sha256=ORIGINAL_APPROVED_PLAN_SHA256,
        expected_amendment_sha256=APPROVED_PROVIDER_AMENDMENT_SHA256,
        expected_trust_override_plan_sha256=APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
        expected_provider={
            "constraint_contract_sha256": "c" * 64,
            "observation_receipt_sha256": "d" * 64,
            "billing_authority_sha256": "e" * 64,
            "workspace_scope_sha256": "8" * 64,
            "environment_scope_sha256": "9" * 64,
            "authoritative_report_identity_sha256": "1" * 64,
            "billing_completeness_delay_seconds": 3600,
            "trust_override_sha256": None,
        },
        now=datetime(2026, 8, 22, 0, 0, tzinfo=UTC),
    )
    assert result["approval_digest"] != result["challenge_sha256"]
    with pytest.raises(ReferenceJobError, match="expired"):
        validate_reference_approval(
            approval,
            expected_challenge_sha256="a" * 64,
            expected_original_plan_sha256=ORIGINAL_APPROVED_PLAN_SHA256,
            expected_amendment_sha256=APPROVED_PROVIDER_AMENDMENT_SHA256,
            expected_trust_override_plan_sha256=APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
            expected_provider={
                "constraint_contract_sha256": "c" * 64,
                "observation_receipt_sha256": "d" * 64,
                "billing_authority_sha256": "e" * 64,
                "workspace_scope_sha256": "8" * 64,
                "environment_scope_sha256": "9" * 64,
                "authoritative_report_identity_sha256": "1" * 64,
                "billing_completeness_delay_seconds": 3600,
                "trust_override_sha256": None,
            },
            now=datetime(2026, 8, 22, 2, 0, tzinfo=UTC),
        )
    with pytest.raises(ReferenceJobError, match="challenge"):
        validate_reference_approval(
            approval,
            expected_challenge_sha256="c" * 64,
            expected_original_plan_sha256=ORIGINAL_APPROVED_PLAN_SHA256,
            expected_amendment_sha256=APPROVED_PROVIDER_AMENDMENT_SHA256,
            expected_trust_override_plan_sha256=APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
            expected_provider={
                "constraint_contract_sha256": "c" * 64,
                "observation_receipt_sha256": "d" * 64,
                "billing_authority_sha256": "e" * 64,
                "workspace_scope_sha256": "8" * 64,
                "environment_scope_sha256": "9" * 64,
                "authoritative_report_identity_sha256": "1" * 64,
                "billing_completeness_delay_seconds": 3600,
                "trust_override_sha256": None,
            },
            now=datetime(2026, 8, 22, 0, 0, tzinfo=UTC),
        )

    old = json.loads(approval.read_text(encoding="utf-8"))
    old.pop("local_reservation_limit_usd")
    old["maximum_cost_usd"] = "4.00"
    approval.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(ReferenceJobError, match="schema is closed"):
        validate_reference_approval(
            approval,
            expected_challenge_sha256="a" * 64,
            expected_original_plan_sha256=ORIGINAL_APPROVED_PLAN_SHA256,
            expected_amendment_sha256=APPROVED_PROVIDER_AMENDMENT_SHA256,
            expected_trust_override_plan_sha256=APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
            expected_provider={
                "constraint_contract_sha256": "c" * 64,
                "observation_receipt_sha256": "d" * 64,
                "billing_authority_sha256": "e" * 64,
                "workspace_scope_sha256": "8" * 64,
                "environment_scope_sha256": "9" * 64,
                "authoritative_report_identity_sha256": "1" * 64,
                "billing_completeness_delay_seconds": 3600,
                "trust_override_sha256": None,
            },
            now=datetime(2026, 8, 22, 0, 0, tzinfo=UTC),
        )


def test_reference_dry_run_records_complete_zero_spend_row(tmp_path: Path) -> None:
    config_path = _config(tmp_path)
    result = plan_reference_dry_run(
        config_path.relative_to(tmp_path),
        Path("results/local/reference.sqlite"),
        tmp_path,
    )
    assert result["job_plan"]["submit"] is False
    assert result["run"]["status"] == "completed"
    assert result["run"]["mode"] == "modal_dry_run"
    assert result["run"]["modal_cost_requested_usd"] == "0"
    assert result["run"]["modal_cost_actual_usd"] == "0"
    assert result["run"]["metrics"]["weights_transferred"]["value"] is False


def _submission_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    forbidden_members = {"App", "remote", "spawn", "deploy", "submit"}
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            violations.extend(
                alias.name for alias in node.names if alias.name.split(".", 1)[0] == "modal"
            )
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] == "modal":
            violations.append(node.module or "modal")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_members:
                violations.append(node.func.id)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_members:
                violations.append(node.func.attr)
            elif (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "__import__"
                    or isinstance(node.func, ast.Attribute)
                    and node.func.attr == "import_module"
                )
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.split(".", 1)[0] == "modal"
            ):
                violations.append("dynamic modal import")
            elif (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in forbidden_members
            ):
                violations.append(str(node.args[1].value))
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for decorator in node.decorator_list:
                name = decorator.id if isinstance(decorator, ast.Name) else None
                member = decorator.attr if isinstance(decorator, ast.Attribute) else None
                if name in forbidden_members or member in forbidden_members:
                    violations.append(str(name or member))
    return violations


def test_u8_submission_primitives_are_absent() -> None:
    production_paths = sorted(Path("src/lowbit_lab").rglob("*.py")) + sorted(
        Path("modal").rglob("*.py")
    )
    for path in production_paths:
        violations = _submission_violations(path.read_text(encoding="utf-8"))
        if path.as_posix() == "src/lowbit_lab/provider_evidence.py":
            assert violations == ["dynamic modal import"], path
            assert "modal.App(" not in path.read_text(encoding="utf-8")
            assert ".spawn(" not in path.read_text(encoding="utf-8")
        elif path.as_posix() == "src/lowbit_lab/modal_adapter.py":
            assert sorted(violations) == ["App", "modal", "spawn"], path
            source = path.read_text(encoding="utf-8")
            assert source.count("modal.App(") == 1
            assert source.count("@app.function(") == 1
            assert source.count("app.run(") == 1
            assert source.count("observe.spawn(") == 1
            assert source.count("call.get(") == 1
            assert "include_source=False" in source
            assert "environment_name=capability.provider_environment" in source
            assert 'serialized=SMOKE_RESOURCE_SPEC["serialized_function"]' in source
            tree = ast.parse(source)
            allowed_attributes = {
                "modal": {"App"},
                "app": {"function", "run"},
                "observe": {"spawn"},
                "call": {"get", "object_id"},
            }
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in allowed_attributes
                ):
                    assert node.attr in allowed_attributes[node.value.id], (
                        node.value.id,
                        node.attr,
                    )
        elif path.as_posix() == "src/lowbit_lab/reference_modal_adapter.py":
            assert sorted(violations) == [
                "App",
                "modal",
                    "modal._serialization",
                    "modal._vendor",
                    "modal._vendor",
                    "modal.config",
                    "spawn",
            ], path
            source = path.read_text(encoding="utf-8")
            assert source.count("modal.App(") == 1
            assert source.count("remote.spawn(") == 1
            assert source.count("app.run(") == 1
            assert source.count("image.build(") == 1
            assert "include_source=False" in source
            assert "retries=0" in source
            assert "gpu=\"A100-80GB:1\"" in source
            for forbidden in (".deploy(", "modal.Secret", "modal.Volume", "mounts=", "schedule="):
                assert forbidden not in source, forbidden
        else:
            assert violations == [], path


@pytest.mark.parametrize(
    "source",
    [
        "import modal.runner",
        "from modal.app import App as CloudApp",
        "App('forbidden')",
        "client.submit()",
        "@client.remote\ndef task():\n    pass",
        "__import__('modal.runner')",
        "importlib.import_module('modal.runner')",
        "getattr(client, 'spawn')()",
    ],
)
def test_no_submit_scanner_rejects_equivalent_primitives(source: str) -> None:
    assert _submission_violations(source)


def test_cli_records_malformed_reference_yaml_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs = tmp_path / "configs" / "local"
    configs.mkdir(parents=True)
    path = configs / "malformed.yaml"
    path.write_text("kind: modal_reference_preview\ninvalid: [\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lowbit-modal-plan",
            "--root",
            str(tmp_path),
            "--config",
            "configs/local/malformed.yaml",
            "--db",
            "results/local/reference.sqlite",
        ],
    )
    with pytest.raises(SystemExit):
        main()
    with sqlite3.connect(tmp_path / "results/local/reference.sqlite") as connection:
        status = connection.execute("SELECT status FROM attempts").fetchone()[0]
    assert status == "failed"
