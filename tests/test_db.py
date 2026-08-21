from pathlib import Path

import pytest

from lowbit_lab.db import DatabaseError, ResultsDatabase


def test_schema_is_idempotent_and_transitions_are_explicit(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    database.initialize()
    database.create_run(
        run_id="run-1",
        experiment_id="experiment-1",
        config_sha256="a" * 64,
        config_json="{}",
        source_hashes={},
        runtime={},
        hardware={},
        phase=0,
        mode="local_dry_run",
        requested_cost="0",
        started_at="2026-08-21T00:00:00+00:00",
    )
    database.transition("run-1", "validated")
    with pytest.raises(DatabaseError, match="invalid transition"):
        database.transition("run-1", "completed", ended_at="2026-08-21T00:00:01+00:00")
    database.transition("run-1", "running")
    database.add_metric("run-1", "proof", False)
    database.transition("run-1", "completed", ended_at="2026-08-21T00:00:01+00:00")
    run = database.get_run("run-1")
    assert run["status"] == "completed"
    assert run["metrics"]["proof"]["value"] is False
    assert [item["to_state"] for item in run["transitions"]] == [
        "created",
        "validated",
        "running",
        "completed",
    ]


def test_experiment_id_cannot_be_rebound(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    common = {
        "experiment_id": "immutable-experiment",
        "source_hashes": {},
        "runtime": {},
        "hardware": {},
        "phase": 0,
        "mode": "local_dry_run",
        "requested_cost": "0",
        "started_at": "2026-08-21T00:00:00+00:00",
    }
    database.create_run(
        run_id="run-1", config_sha256="a" * 64, config_json='{"version":1}', **common
    )
    with pytest.raises(DatabaseError, match="different config"):
        database.create_run(
            run_id="run-2", config_sha256="b" * 64, config_json='{"version":2}', **common
        )
