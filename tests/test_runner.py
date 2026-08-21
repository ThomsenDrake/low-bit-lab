import shutil
from pathlib import Path

import pytest
import yaml

from lowbit_lab.audit import begin_attempt, failure_reason
from lowbit_lab.config import ConfigError, load_experiment_config, verify_activation_authority
from lowbit_lab.db import DatabaseError, ResultsDatabase
from lowbit_lab.modal_job import plan_modal_dry_run
from lowbit_lab.runner import run_local_dry_run

ROOT = Path(__file__).parents[1]


def make_project(tmp_path: Path) -> Path:
    (tmp_path / "configs").mkdir()
    (tmp_path / "results").mkdir()
    shutil.copy2(ROOT / "PLAN.md", tmp_path / "PLAN.md")
    for name in (
        "budget-policy.json",
        "example-local-dry-run.yaml",
        "example-modal-dry-run.yaml",
    ):
        shutil.copy2(ROOT / "configs" / name, tmp_path / "configs" / name)
    return tmp_path


def test_local_dry_run_records_complete_zero_spend_row(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    payload = run_local_dry_run(
        root / "configs/example-local-dry-run.yaml",
        root / "results/local.sqlite",
        root,
    )
    run = payload["run"]
    assert run["status"] == "completed"
    assert run["modal_cost_actual_usd"] == "0"
    assert run["metrics"]["weights_loaded"]["value"] is False
    assert run["metrics"]["useful_context_proven"]["value"] is False


def test_modal_dry_run_plans_but_never_submits(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    payload = plan_modal_dry_run(
        root / "configs/example-modal-dry-run.yaml",
        root / "results/modal.sqlite",
        root,
        dry_run=True,
    )
    assert payload["job_plan"]["submit"] is False
    assert payload["run"]["status"] == "completed"
    assert payload["run"]["metrics"]["modal_submitted"]["value"] is False


def test_workflows_reject_database_outside_results(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    with pytest.raises(DatabaseError, match="under repository results"):
        run_local_dry_run(
            root / "configs/example-local-dry-run.yaml", root / "outside.sqlite", root
        )


def test_source_hash_failure_is_audited(tmp_path: Path) -> None:
    root = make_project(tmp_path)
    config_path = root / "configs/example-local-dry-run.yaml"
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["sources"][0]["sha256"] = "0" * 64
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    db_path = root / "results/failure.sqlite"
    with pytest.raises(ConfigError, match="source hash mismatch"):
        run_local_dry_run(config_path, db_path, root)
    database = ResultsDatabase(db_path)
    with database.connect() as connection:
        row = connection.execute("SELECT * FROM attempts").fetchone()
    assert row["status"] == "failed"
    assert "source hash mismatch" in row["failure_reason"]


@pytest.mark.parametrize("failure_kind", ["missing", "changed"])
def test_invalid_activation_authority_is_audited_before_run_link(
    tmp_path: Path, failure_kind: str
) -> None:
    root = make_project(tmp_path)
    source = yaml.safe_load((ROOT / "configs/example-local-activation.yaml").read_text())
    source["experiment_id"] = "generic-executable-activation-v1"
    source["activation"].update(
        {
            "preview_only": False,
            "approved_plan_sha256": "1" * 64,
            "runtime_lock_sha256": "2" * 64,
            "metadata_policy_sha256": "3" * 64,
            "evaluation_lock_sha256": "4" * 64,
        }
    )
    source["target"].update(
        {
            "status": "configured",
            "identifier": "organization/repository",
            "revision": "a" * 40,
            "license": "example-license",
        }
    )
    if failure_kind == "missing":
        source["activation"]["evaluation_lock_sha256"] = None
    config_path = root / "configs/local-activation.yaml"
    config_path.write_text(yaml.safe_dump(source), encoding="utf-8")
    database = ResultsDatabase(root / "results/activation.sqlite")
    database.initialize()
    attempt_id = begin_attempt(
        database, config_path, root, "2026-08-21T00:00:00+00:00"
    )
    with pytest.raises(ConfigError) as raised:
        config = load_experiment_config(config_path)
        observed = config.activation.authority_hashes
        observed["evaluation_lock_sha256"] = "f" * 64
        verify_activation_authority(config, observed)
    database.fail_attempt(
        attempt_id, failure_reason(raised.value), "2026-08-21T00:00:01+00:00"
    )
    with database.connect() as connection:
        attempt = connection.execute("SELECT * FROM attempts").fetchone()
        run_count = connection.execute("SELECT count(*) FROM experiments").fetchone()[0]
    assert attempt["status"] == "failed"
    assert run_count == 0
