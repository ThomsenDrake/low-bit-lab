import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lowbit_lab.db import SCHEMA_VERSION, DatabaseError, ResultsDatabase
from lowbit_lab.reference_contract import (
    APPROVED_PROVIDER_AMENDMENT_PATH,
    APPROVED_PROVIDER_AMENDMENT_SHA256,
    ORIGINAL_APPROVED_PLAN_PATH,
    ORIGINAL_APPROVED_PLAN_SHA256,
    reference_execution_scope_sha256,
)


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
        assert (
            connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            == SCHEMA_VERSION
        )
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
    mutate_config: Callable[[dict[str, object]], None] | None = None,
    observation_receipt_sha256: str = "b" * 64,
) -> None:
    inputs = {
        "source_revision": "d" * 40,
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
        "original_approved_plan_path": ORIGINAL_APPROVED_PLAN_PATH,
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "approved_amendment_path": APPROVED_PROVIDER_AMENDMENT_PATH,
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
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
            "workspace_scope_sha256": "8" * 64,
            "environment_scope_sha256": "9" * 64,
            "constraint_contract_path": "reports/local/constraint.json",
            "constraint_contract_sha256": "a" * 64,
            "observation_receipt_path": "reports/local/observation.json",
            "observation_receipt_sha256": observation_receipt_sha256,
            "billing_authority_path": "reports/local/billing.json",
            "billing_authority_sha256": "c" * 64,
        },
        "gates": {
            "formula_authority_path": None,
            "memory_fit_evidence_path": None,
            "memory_fit_evidence_sha256": None,
            "cold_path_time_evidence_path": None,
            "cold_path_time_evidence_sha256": None,
        },
        "approval_artifact_path": None,
    }
    if mutate_config is not None:
        mutate_config(raw)
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
    approval = hashlib.sha256(f"approval-{suffix}".encode()).hexdigest()
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


def _downgrade_populated_database_to_v4(path: Path) -> None:
    database = ResultsDatabase(path)
    database.initialize()
    _reserve(database, suffix="legacy-v4")
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.executescript(
            """
            CREATE TABLE experiments_v4_legacy (
                run_id TEXT PRIMARY KEY,
                experiment_id TEXT NOT NULL REFERENCES experiment_configs(experiment_id),
                config_sha256 TEXT NOT NULL, config_json TEXT NOT NULL,
                source_hashes_json TEXT NOT NULL, runtime_json TEXT NOT NULL,
                hardware_json TEXT NOT NULL, phase INTEGER NOT NULL, mode TEXT NOT NULL,
                status TEXT NOT NULL, modal_cost_requested_usd TEXT NOT NULL,
                modal_cost_actual_usd TEXT NOT NULL DEFAULT '0', failure_reason TEXT,
                owner_id TEXT, lease_expires_at TEXT, heartbeat_at TEXT,
                started_at TEXT NOT NULL, ended_at TEXT
            );
            INSERT INTO experiments_v4_legacy
            SELECT run_id, experiment_id, config_sha256, config_json, source_hashes_json,
                   runtime_json, hardware_json, phase, mode, status,
                   modal_cost_requested_usd, coalesce(modal_cost_actual_usd, '0'),
                   failure_reason, owner_id, lease_expires_at, heartbeat_at, started_at, ended_at
            FROM experiments;
            CREATE TABLE budget_reservations_v4_legacy (
                reservation_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES experiments_v4_legacy(run_id),
                experiment_id TEXT NOT NULL, phase INTEGER NOT NULL, status TEXT NOT NULL,
                requested_cost_usd TEXT NOT NULL, provider_actual_cost_usd TEXT,
                provider_job_id TEXT UNIQUE, app_identity TEXT,
                idempotency_key TEXT NOT NULL UNIQUE, settlement_identity TEXT UNIQUE,
                owner_id TEXT NOT NULL, lease_expires_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL, failure_reason TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            INSERT INTO budget_reservations_v4_legacy
            SELECT reservation_id, run_id, experiment_id, phase, status, requested_cost_usd,
                   provider_actual_cost_usd, provider_job_id, app_identity, idempotency_key,
                   settlement_identity, owner_id, lease_expires_at, heartbeat_at,
                   failure_reason, created_at, updated_at
            FROM budget_reservations;
            DROP INDEX budget_reservations_active_experiment;
            DROP INDEX budget_reservations_reference_scope;
            DROP TABLE budget_reservations;
            DROP INDEX experiments_config_sha;
            DROP TABLE experiments;
            ALTER TABLE experiments_v4_legacy RENAME TO experiments;
            ALTER TABLE budget_reservations_v4_legacy RENAME TO budget_reservations;
            CREATE INDEX experiments_config_sha ON experiments(config_sha256);
            CREATE UNIQUE INDEX budget_reservations_active_experiment
            ON budget_reservations(experiment_id)
            WHERE status IN ('reserved', 'submitted', 'settlement_pending', 'audit_blocked');
            DELETE FROM schema_info;
            INSERT INTO schema_info(version, applied_at) VALUES (4, '2026-08-22T00:00:00Z');
            """
        )


def test_populated_v4_migration_preserves_legacy_rows_without_scope_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v4.sqlite"
    _downgrade_populated_database_to_v4(path)
    database = ResultsDatabase(path)
    database.initialize()
    with database.connect() as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 5
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        legacy = connection.execute(
            "SELECT reference_execution_scope_sha256 FROM budget_reservations"
        ).fetchone()[0]
        actual = connection.execute(
            "SELECT modal_cost_actual_usd FROM experiments"
        ).fetchone()[0]
    assert legacy is None
    assert actual == "0"


def test_v4_to_v5_migration_rolls_back_on_unknown_schema_state(tmp_path: Path) -> None:
    path = tmp_path / "rollback.sqlite"
    _downgrade_populated_database_to_v4(path)
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE experiments_v5(blocker INTEGER)")
    with pytest.raises(DatabaseError, match="v5 migration failed"):
        ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 4
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(budget_reservations)")
        }
    assert "reference_execution_scope_sha256" not in columns


def test_reference_execution_scope_is_canonical_and_source_bound() -> None:
    scope = reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
    )
    assert len(scope) == 64
    assert scope == reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
    )
    with pytest.raises(ValueError, match="source revision"):
        reference_execution_scope_sha256(
            source_revision="D" * 40,
            weight_inventory_sha256="1" * 64,
            evaluation_lock_sha256="4" * 64,
            formula_authority_sha256="5" * 64,
        )


def test_reference_reservation_is_atomic_and_prevents_cap_overlap(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="one")
    with pytest.raises(DatabaseError, match="cap"):
        _reserve(database, suffix="two")
    assert database.get_attempt("attempt-two")["status"] == "received"
    assert database.get_reservation("reservation-one")["status"] == "reserved"
    assert database.get_run("run-one")["modal_cost_actual_usd"] is None
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


def _remove_provider_field(raw: dict[str, object], field: str) -> None:
    provider = raw["provider"]
    assert isinstance(provider, dict)
    provider.pop(field)


def _set_provider_field(raw: dict[str, object], field: str, value: object) -> None:
    provider = raw["provider"]
    assert isinstance(provider, dict)
    provider[field] = value


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw.pop("approved_amendment_sha256"), "schema"),
        (
            lambda raw: raw.__setitem__("approved_amendment_sha256", "f" * 64),
            "authority",
        ),
        (
            lambda raw: raw.__setitem__(
                "approved_amendment_path", "docs/plans/local/wrong.md"
            ),
            "authority",
        ),
        (lambda raw: _remove_provider_field(raw, "constraint_contract_path"), "schema"),
        (
            lambda raw: _set_provider_field(raw, "observation_receipt_sha256", None),
            "authority",
        ),
        (lambda raw: _remove_provider_field(raw, "workspace_scope_sha256"), "schema"),
        (
            lambda raw: _set_provider_field(raw, "billing_authority_path", "C:/private"),
            "authority",
        ),
        (
            lambda raw: _set_provider_field(
                raw, "billing_authority_path", "reports/local/../private.json"
            ),
            "authority",
        ),
    ],
)
def test_reference_database_boundary_rejects_authority_bypass(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match=message):
        _reserve(database, suffix="bypass", mutate_config=mutation)


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
    assert database.get_run("run-settle")["modal_cost_actual_usd"] == "2.50"
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

    _reserve(database, suffix="post", observation_receipt_sha256="e" * 64)
    database.mark_reservation_submitted(
        "reservation-post",
        provider_job_id="job-post",
        app_identity="isolated-app-post",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    blocked = database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert blocked == {"released": [], "audit_blocked": ["reservation-post"]}
    assert database.get_run("run-post")["modal_cost_actual_usd"] is None


def test_released_scope_requires_new_observation_challenge_and_approval(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="first")
    database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")

    with pytest.raises(DatabaseError, match="observation"):
        _reserve(database, suffix="same-observation")

    _reserve(
        database,
        suffix="fresh",
        observation_receipt_sha256="e" * 64,
    )
    assert database.get_reservation("reservation-fresh")["status"] == "reserved"
    with database.connect() as connection:
        consumed = connection.execute(
            "SELECT count(*) FROM reference_approval_challenges WHERE consumed_at IS NOT NULL"
        ).fetchone()[0]
    assert consumed == 2


@pytest.mark.parametrize(
    "terminal", ["submitted", "settlement_pending", "settled", "audit_blocked", "failed"]
)
def test_submitted_or_later_scope_is_permanently_consumed(
    tmp_path: Path, terminal: str
) -> None:
    database = ResultsDatabase(tmp_path / f"{terminal}.sqlite")
    database.initialize()
    _reserve(database, suffix=f"used-{terminal}")
    reservation_id = f"reservation-used-{terminal}"
    database.mark_reservation_submitted(
        reservation_id,
        provider_job_id=f"job-{terminal}",
        app_identity=f"app-{terminal}",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    if terminal == "settlement_pending":
        database.mark_settlement_pending(
            reservation_id, occurred_at="2026-08-22T00:02:00+00:00"
        )
    elif terminal == "settled":
        database.settle_reservation(
            reservation_id,
            actual_cost_usd="4.00",
            settlement_identity=f"bill-{terminal}",
            occurred_at="2026-08-22T00:03:00+00:00",
        )
    elif terminal == "audit_blocked":
        database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    elif terminal == "failed":
        with pytest.raises(DatabaseError, match="budget failure"):
            database.settle_reservation(
                reservation_id,
                actual_cost_usd="4.01",
                settlement_identity=f"bill-{terminal}",
                occurred_at="2026-08-22T00:03:00+00:00",
            )

    with pytest.raises(DatabaseError, match="scope"):
        _reserve(
            database,
            suffix=f"retry-{terminal}",
            observation_receipt_sha256="e" * 64,
        )


def test_concurrent_connections_cannot_reserve_the_same_scope_twice(tmp_path: Path) -> None:
    path = tmp_path / "race.sqlite"
    ResultsDatabase(path).initialize()

    def reserve(suffix: str, observation: str) -> str:
        try:
            _reserve(
                ResultsDatabase(path),
                suffix=suffix,
                observation_receipt_sha256=observation,
            )
        except DatabaseError as exc:
            return str(exc)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda args: reserve(*args),
                [("race-a", "e" * 64), ("race-b", "f" * 64)],
            )
        )
    assert outcomes.count("ok") == 1
    assert any("cap" in outcome for outcome in outcomes if outcome != "ok")


def test_over_cap_settlement_is_durable_and_unambiguously_fails(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="over")
    database.mark_reservation_submitted(
        "reservation-over",
        provider_job_id="job-over",
        app_identity="app-over",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    with pytest.raises(DatabaseError, match="budget failure"):
        database.settle_reservation(
            "reservation-over",
            actual_cost_usd="4.01",
            settlement_identity="billing-over",
            occurred_at="2026-08-22T00:03:00+00:00",
        )
    reservation = database.get_reservation("reservation-over")
    assert reservation["status"] == "failed"
    assert reservation["provider_actual_cost_usd"] == "4.01"
    assert reservation["settlement_identity"] == "billing-over"
    run = database.get_run("run-over")
    assert run["status"] == "failed"
    assert run["modal_cost_actual_usd"] == "4.01"
    with pytest.raises(DatabaseError, match="cap"):
        _reserve(
            database,
            suffix="different-scope-after-over",
            observation_receipt_sha256="e" * 64,
            mutate_config=lambda raw: raw["inputs"].__setitem__(
                "source_revision", "e" * 40
            ),
        )


def test_delayed_authoritative_billing_can_settle_an_audit_blocked_run(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="delayed")
    database.mark_reservation_submitted(
        "reservation-delayed",
        provider_job_id="job-delayed",
        app_identity="app-delayed",
        occurred_at="2026-08-22T00:01:00+00:00",
    )
    database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert database.get_run("run-delayed")["modal_cost_actual_usd"] is None
    database.settle_reservation(
        "reservation-delayed",
        actual_cost_usd="4.00",
        settlement_identity="billing-delayed",
        occurred_at="2026-08-22T01:00:00+00:00",
    )
    assert database.get_reservation("reservation-delayed")["status"] == "settled"
    assert database.get_run("run-delayed")["modal_cost_actual_usd"] == "4.00"
