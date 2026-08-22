import hashlib
import json
from pathlib import Path

import pytest

from lowbit_lab.db import SCHEMA_VERSION, DatabaseError, ResultsDatabase


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


V1_SCHEMA = """
CREATE TABLE schema_info (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE experiment_configs (
    experiment_id TEXT PRIMARY KEY, config_sha256 TEXT NOT NULL,
    config_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE experiments (
    run_id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
    config_sha256 TEXT NOT NULL, config_json TEXT NOT NULL, source_hashes_json TEXT NOT NULL,
    runtime_json TEXT NOT NULL, hardware_json TEXT NOT NULL, phase INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('local_dry_run', 'modal_dry_run')),
    status TEXT NOT NULL, modal_cost_requested_usd TEXT NOT NULL,
    modal_cost_actual_usd TEXT NOT NULL, failure_reason TEXT, started_at TEXT NOT NULL,
    ended_at TEXT
);
CREATE TABLE state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    from_state TEXT, to_state TEXT NOT NULL, reason TEXT, occurred_at TEXT NOT NULL
);
CREATE TABLE metrics (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    name TEXT NOT NULL, value_json TEXT NOT NULL, unit TEXT, PRIMARY KEY (run_id, name)
);
CREATE TABLE artifacts (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    path TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
    kind TEXT NOT NULL, PRIMARY KEY (run_id, path)
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY, config_path TEXT NOT NULL, raw_config_sha256 TEXT,
    status TEXT NOT NULL, run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
    failure_reason TEXT, started_at TEXT NOT NULL, ended_at TEXT
);
INSERT INTO schema_info VALUES (1, '2026-08-21T00:00:00Z');
INSERT INTO experiment_configs VALUES ('legacy-experiment', printf('%064d', 0), '{}', 'created');
INSERT INTO experiments VALUES (
    'legacy-run', 'legacy-experiment', printf('%064d', 0), '{}', '{}', '{}', '{}', 0,
    'local_dry_run', 'completed', '0', '0', NULL, 'started', 'ended'
);
INSERT INTO state_transitions(run_id, from_state, to_state, reason, occurred_at)
VALUES ('legacy-run', 'running', 'completed', NULL, 'transitioned');
INSERT INTO metrics VALUES ('legacy-run', 'proof', 'false', NULL);
INSERT INTO artifacts VALUES ('legacy-run', 'artifact.bin', printf('%064d', 1), 1, 'proof');
INSERT INTO attempts VALUES (
    'legacy-attempt', 'configs/legacy.yaml', printf('%064d', 2), 'linked',
    'legacy-run', NULL, 'started', 'ended'
);
"""


def executable_activation_json(*, preview_only: bool = False) -> str:
    return json.dumps(
        {
            "mode": "local_activation",
            "weights_required": False,
            "target": {
                "status": "configured",
                "identifier": "organization/repository",
                "revision": "a" * 40,
                "license": "example-license",
            },
            "modal": {
                "requested_cost_usd": "0",
                "gpu_type": "none",
                "gpu_count": 0,
                "submit": False,
                "cleanup": "retain",
            },
            "privacy": {"allow_cloud_upload": False},
            "activation": {
                "preview_only": preview_only,
                "approved_plan_sha256": "1" * 64,
                "runtime_decision_sha256": "5" * 64,
                "runtime_lock_sha256": "2" * 64,
                "metadata_policy_sha256": "3" * 64,
                "evaluation_lock_sha256": "4" * 64,
                "scheduling_enabled": False,
                "destructive_cleanup_enabled": False,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_populated_v1_database_migrates_without_losing_evidence(tmp_path: Path) -> None:
    path = tmp_path / "results.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.executescript(V1_SCHEMA)

    database = ResultsDatabase(path)
    database.initialize()

    with database.connect() as connection:
        assert (
            connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            == SCHEMA_VERSION
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        counts = {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "experiment_configs",
                "experiments",
                "state_transitions",
                "metrics",
                "artifacts",
                "attempts",
            )
        }
        mode_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'experiments'"
        ).fetchone()[0]
    assert counts == {table: 1 for table in counts}
    assert "local_activation" in mode_sql
    legacy = database.get_run("legacy-run")
    assert legacy["config"] == {}
    assert legacy["source_hashes"] == {}
    assert legacy["metrics"]["proof"]["value"] is False
    assert legacy["transitions"][0]["to_state"] == "completed"
    assert database.get_attempt("legacy-attempt")["run_id"] == "legacy-run"


def test_schema_v2_accepts_truthful_activation_mode(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    database.create_run(
        run_id="activation-run",
        experiment_id="activation-experiment",
        config_sha256="a" * 64,
        config_json=executable_activation_json(),
        source_hashes={},
        runtime={},
        hardware={},
        phase=1,
        mode="local_activation",
        requested_cost="0",
        started_at="2026-08-21T00:00:00+00:00",
    )
    assert database.get_run("activation-run")["mode"] == "local_activation"


def test_preview_activation_cannot_create_or_link_a_run(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="not executable"):
        database.create_run(
            run_id="preview-run",
            experiment_id="preview-experiment",
            config_sha256="a" * 64,
            config_json=executable_activation_json(preview_only=True),
            source_hashes={},
            runtime={},
            hardware={},
            phase=1,
            mode="local_activation",
            requested_cost="0",
            started_at="2026-08-21T00:00:00+00:00",
        )
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM experiment_configs").fetchone()[0] == 0


def test_activation_experiment_id_cannot_change_authority_hashes(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    common = {
        "experiment_id": "immutable-activation",
        "source_hashes": {},
        "runtime": {},
        "hardware": {},
        "phase": 1,
        "mode": "local_activation",
        "requested_cost": "0",
        "started_at": "2026-08-21T00:00:00+00:00",
    }
    first_json = executable_activation_json()
    database.create_run(
        run_id="activation-1", config_sha256="a" * 64, config_json=first_json, **common
    )
    changed = json.loads(first_json)
    changed["activation"]["runtime_lock_sha256"] = "f" * 64
    changed_json = json.dumps(changed, sort_keys=True, separators=(",", ":"))
    with pytest.raises(DatabaseError, match="different config"):
        database.create_run(
            run_id="activation-2",
            config_sha256="b" * 64,
            config_json=changed_json,
            **common,
        )


def test_failed_v1_migration_rolls_back_schema_and_evidence(tmp_path: Path) -> None:
    path = tmp_path / "results.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.executescript(V1_SCHEMA)
        connection.execute("UPDATE experiments SET status = 'unknown'")

    with pytest.raises(DatabaseError, match="migration failed"):
        ResultsDatabase(path).initialize()

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 1
        assert connection.execute("SELECT status FROM experiments").fetchone()[0] == "unknown"
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE '%_v2'"
        ).fetchone()[0] == 0


def _v2_schema() -> str:
    return V1_SCHEMA.replace(
        "mode TEXT NOT NULL CHECK(mode IN ('local_dry_run', 'modal_dry_run'))",
        "mode TEXT NOT NULL CHECK(mode IN ('local_dry_run', 'modal_dry_run', 'local_activation'))",
    ).replace(
        "INSERT INTO schema_info VALUES (1, '2026-08-21T00:00:00Z')",
        "INSERT INTO schema_info VALUES (2, '2026-08-21T00:00:00Z')",
    )


def test_populated_v2_database_migrates_additively_without_losing_u2_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "results.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.executescript(_v2_schema())
    ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 4
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info('experiments')").fetchall()
        }
        assert {"owner_id", "lease_expires_at", "heartbeat_at"} <= columns
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_failed_v2_to_v3_migration_rolls_back_added_columns(tmp_path: Path) -> None:
    path = tmp_path / "results.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.executescript(_v2_schema())
        connection.execute("CREATE TABLE activation_gates(blocker INTEGER)")
    with pytest.raises(DatabaseError, match="v3 migration failed"):
        ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 2
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info('experiments')").fetchall()
        }
        assert "owner_id" not in columns
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1


def _reserve(
    database: ResultsDatabase,
    *,
    suffix: str,
    amount: str = "4.00",
    attach_approval: bool = True,
    tamper_config_after_challenge: bool = False,
    hardware: dict[str, object] | None = None,
) -> None:
    inputs = {
        "weight_inventory_sha256": "1" * 64,
        "weight_inventory_tensor_bytes": 55,
        "provenance_manifest_sha256": "2" * 64,
        "runtime_receipt_sha256": "3" * 64,
        "evaluation_lock_sha256": "4" * 64,
        "evaluation_max_context_tokens": 32768,
        "formula_authority_sha256": "5" * 64,
        "reviewed_commit_sha256": "6" * 40,
        "control_plane_sha256": "7" * 64,
    }
    raw = {
        "schema_version": 1,
        "kind": "modal_reference_preview",
        "experiment_id": f"reference-{suffix}",
        "approved_plan_path": "docs/plans/local/approved.md",
        "approved_plan_sha256": "8" * 64,
        "budget_policy_path": "configs/local/reference-budget.json",
        "inputs": inputs,
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
    config_json = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    config_sha256 = hashlib.sha256(config_json.encode()).hexdigest()
    challenge_material = dict(raw)
    challenge_material.pop("approval_artifact_path")
    challenge = hashlib.sha256(
        json.dumps(
            challenge_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()
    if tamper_config_after_challenge:
        raw["experiment_id"] = f"tampered-{suffix}"
        config_json = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        config_sha256 = hashlib.sha256(config_json.encode()).hexdigest()
    approval = (suffix[-1] if suffix else "b") * 64
    if not approval[0].isalnum() or approval[0].lower() not in "abcdef0123456789":
        approval = "b" * 63 + str(len(suffix) % 10)
    database.register_reference_challenge(
        challenge_sha256=challenge,
        packet_sha256="c" * 64,
        created_at="2026-08-22T00:00:00+00:00",
    )
    if attach_approval:
        database.attach_reference_approval(
            challenge_sha256=challenge,
            approval_digest=approval,
            expires_at="2026-08-22T01:00:00+00:00",
        )
    database.create_attempt(
        attempt_id=f"attempt-{suffix}",
        config_path="configs/local/reference.yaml",
        raw_config_sha256="a" * 64,
        started_at="2026-08-22T00:00:00+00:00",
    )
    database.reserve_reference_run(
        reservation_id=f"reservation-{suffix}",
        attempt_id=f"attempt-{suffix}",
        run_id=f"run-{suffix}",
        experiment_id=f"reference-{suffix}",
        config_sha256=config_sha256,
        config_json=config_json,
        source_hashes={
            name: value
            for name, value in inputs.items()
            if name not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
            and value is not None
        },
        runtime={"receipt_sha256": inputs["runtime_receipt_sha256"]},
        hardware=hardware or {},
        requested_cost_usd=amount,
        phase_cap_usd="4.00",
        total_cap_usd="4.00",
        single_job_cap_usd="4.00",
        idempotency_key=f"idempotency-{suffix}",
        owner_id="owner",
        lease_expires_at="2026-08-22T00:05:00+00:00",
        started_at="2026-08-22T00:00:00+00:00",
        challenge_sha256=challenge,
        approval_digest=approval,
    )


def test_reference_reservation_is_atomic_and_prevents_cap_overlap(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="one")
    with pytest.raises(DatabaseError, match="cap"):
        _reserve(database, suffix="two")
    assert database.get_attempt("attempt-two")["status"] == "received"
    assert database.get_reservation("reservation-one")["status"] == "reserved"
    with database.connect() as connection:
        assert connection.execute(
            "SELECT count(*) FROM experiments WHERE run_id = 'run-two'"
        ).fetchone()[0] == 0


def test_reference_reservation_requires_unconsumed_unexpired_approval(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="approval"):
        _reserve(database, suffix="missing", attach_approval=False)
    assert database.get_attempt("attempt-missing")["status"] == "received"


def test_reference_reservation_binds_config_cap_expiry_and_private_data(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="bound to the canonical config"):
        _reserve(database, suffix="drift", tamper_config_after_challenge=True)

    database = ResultsDatabase(tmp_path / "cap.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="USD 4.00"):
        _reserve(database, suffix="cap", amount="3.99")

    database = ResultsDatabase(tmp_path / "private.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="credential-shaped"):
        _reserve(database, suffix="private", hardware={"api_key": "do-not-store"})

    database = ResultsDatabase(tmp_path / "expiry.sqlite")
    database.initialize()
    database.register_reference_challenge(
        challenge_sha256="a" * 64,
        packet_sha256="b" * 64,
        created_at="2026-08-22T00:00:00+00:00",
    )
    with pytest.raises(DatabaseError, match="timezone-aware"):
        database.attach_reference_approval(
            challenge_sha256="a" * 64,
            approval_digest="c" * 64,
            expires_at="2026-08-22T01:00:00",
        )


def test_reference_settlement_is_exactly_once_and_provider_attributed(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="settle")
    database.mark_reservation_submitted(
        "reservation-settle",
        provider_job_id="job-1",
        app_identity="isolated-app-1",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    database.mark_settlement_pending(
        "reservation-settle", occurred_at="2026-08-22T00:02:00+00:00"
    )
    database.settle_reservation(
        "reservation-settle",
        actual_cost_usd="2.50",
        settlement_identity="billing-export-row-1",
        occurred_at="2026-08-22T01:00:00+00:00",
    )
    reservation = database.get_reservation("reservation-settle")
    assert reservation["status"] == "settled"
    assert reservation["provider_actual_cost_usd"] == "2.50"
    with pytest.raises(DatabaseError, match="cannot settle"):
        database.settle_reservation(
            "reservation-settle",
            actual_cost_usd="2.50",
            settlement_identity="billing-export-row-1",
            occurred_at="2026-08-22T01:00:01+00:00",
        )


def test_stale_reference_reservations_release_only_before_submission(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="pre")
    released = database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert released == {"released": ["reservation-pre"], "audit_blocked": []}
    assert database.get_run("run-pre")["status"] == "failed"

    _reserve(database, suffix="post")
    database.mark_reservation_submitted(
        "reservation-post",
        provider_job_id="job-post",
        app_identity="isolated-app-post",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    blocked = database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert blocked == {"released": [], "audit_blocked": ["reservation-post"]}
