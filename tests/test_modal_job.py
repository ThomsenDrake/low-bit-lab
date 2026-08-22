import hashlib
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from lowbit_lab.modal_job import (
    ReferenceJobError,
    load_reference_job_config,
    main,
    plan_reference_dry_run,
    plan_reference_preview,
    redact_provider_output,
    validate_reference_approval,
)


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
    approved_plan = plans / "approved.md"
    approved_plan.write_text("approved plan fixture\n", encoding="utf-8")
    plan_sha256 = hashlib.sha256(approved_plan.read_bytes()).hexdigest()
    _budget(configs / "reference-budget.json", plan_sha256)
    raw = {
        "schema_version": 1,
        "kind": "modal_reference_preview",
        "experiment_id": "reference-preview-v1",
        "approved_plan_path": "docs/plans/local/approved.md",
        "approved_plan_sha256": plan_sha256,
        "budget_policy_path": "configs/local/reference-budget.json",
        "inputs": {
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
            "ephemeral_disk_gib": 90,
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
            "safety_evidence_path": None,
            "safety_evidence_sha256": None,
        },
        "gates": {
            "memory_fit_evidence_path": None,
            "memory_fit_evidence_sha256": None,
            "cold_path_time_evidence_path": None,
            "cold_path_time_evidence_sha256": None,
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
    assert preview["submit"] is False
    assert preview["actual_cost_usd"] == "0"
    assert preview["maximum_cost_usd"] == "4.00"
    assert preview["estimated_cost_usd"] == "2.73218400"
    assert preview["resources"] == {
        "gpu_type": "A100-80GB",
        "gpu_count": 1,
        "cpu_cores": 8,
        "memory_gib": 96,
        "ephemeral_disk_gib": 90,
        "timeout_seconds": 2700,
        "startup_timeout_seconds": None,
        "retries": 0,
    }
    assert "formula_authority_missing" in preview["blockers"]
    assert "execution_approval_missing" in preview["blockers"]
    assert len(preview["challenge_sha256"]) == 64


def test_reference_preview_derives_gates_from_hashed_evidence(tmp_path: Path) -> None:
    path = _config(tmp_path)
    reports = tmp_path / "reports" / "local"
    reports.mkdir(parents=True)
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
                "method_sha256": "f" * 64,
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
                "method_sha256": "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["inputs"]["formula_authority_sha256"] = "f" * 64
    raw["gates"] = {
        "memory_fit_evidence_path": "reports/local/memory.json",
        "memory_fit_evidence_sha256": hashlib.sha256(memory.read_bytes()).hexdigest(),
        "cold_path_time_evidence_path": "reports/local/time.json",
        "cold_path_time_evidence_sha256": hashlib.sha256(timing.read_bytes()).hexdigest(),
    }
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_reference_job_config(path, root=tmp_path)
    blockers = plan_reference_preview(config, root=tmp_path)["blockers"]
    assert "memory_fit_unproven" not in blockers
    assert "cold_path_time_budget_unproven" not in blockers

    memory.write_text("{}", encoding="utf-8")
    blockers = plan_reference_preview(config, root=tmp_path)["blockers"]
    assert "memory_fit_unproven" in blockers


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
def test_reference_resource_drift_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
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


def test_provider_output_is_bounded_and_redacted() -> None:
    output = redact_provider_output(
        "modal_token_id=" + "identifier "
        + "modal_token_secret:" + "supersecret "
        + "api_key=" + "anothersecret "
        + '{"password":"' + 'json-secret"} '
        + "Authorization: Bearer " + "bearer-secret "
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
                "schema_version": 1,
                "kind": "reference_execution_approval",
                "challenge_sha256": "a" * 64,
                "reviewed_commit_sha256": "b" * 40,
                "maximum_cost_usd": "4.00",
                "expires_at": "2026-08-22T01:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    result = validate_reference_approval(
        approval,
        expected_challenge_sha256="a" * 64,
        now=datetime(2026, 8, 22, 0, 0, tzinfo=UTC),
    )
    assert result["approval_digest"] != result["challenge_sha256"]
    with pytest.raises(ReferenceJobError, match="expired"):
        validate_reference_approval(
            approval,
            expected_challenge_sha256="a" * 64,
            now=datetime(2026, 8, 22, 2, 0, tzinfo=UTC),
        )
    with pytest.raises(ReferenceJobError, match="challenge"):
        validate_reference_approval(
            approval,
            expected_challenge_sha256="c" * 64,
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


def test_u8_submission_primitives_are_absent() -> None:
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (Path("src/lowbit_lab/modal_job.py"), Path("modal/reference_job.py"))
    )
    for forbidden in ("modal.App", ".remote(", ".spawn(", ".deploy("):
        assert forbidden not in production


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
