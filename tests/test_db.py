import hashlib
import json
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_RECOVERY_AUTHORITY_SHA256,
)
from lowbit_lab.db import (
    SCHEMA_VERSION,
    DatabaseError,
    ResultsDatabase,
    _committed_provider_cost,
)
from lowbit_lab.handoff import sha256_json
from lowbit_lab.reference_authority import (
    AUTHORITY_PATH,
    BOOTSTRAP_AUTHORITY_PATH,
    BOOTSTRAP_STATEMENT_PATH,
    CONTROLLING_PLANS,
    RECOVERY_AUTHORITY_PATH,
    RECOVERY_STATEMENT_PATH,
    SIGNED_CDN_AUTHORITY_PATH,
    SIGNED_CDN_STATEMENT_PATH,
    STATEMENT_PATH,
    build_reference_recovery_authority,
)
from lowbit_lab.reference_contract import (
    APPROVED_PROVIDER_AMENDMENT_PATH,
    APPROVED_PROVIDER_AMENDMENT_SHA256,
    APPROVED_TRUST_OVERRIDE_PLAN_PATH,
    APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
    APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256,
    ORIGINAL_APPROVED_PLAN_PATH,
    ORIGINAL_APPROVED_PLAN_SHA256,
    REFERENCE_CONFIG_SCHEMA_VERSION,
    REFERENCE_GATE_FIELDS,
    reference_execution_scope_sha256,
)
from lowbit_lab.reference_settlement import AUTH_METHOD_SHA256, CANONICAL_EMPTY_REPORT


def _authority_root(database: ResultsDatabase) -> Path:
    root = database.path.parent / "authority-root"
    repository = Path(__file__).resolve().parents[1]
    relative_paths = [
        STATEMENT_PATH,
        AUTHORITY_PATH,
        BOOTSTRAP_STATEMENT_PATH,
        BOOTSTRAP_AUTHORITY_PATH,
        SIGNED_CDN_STATEMENT_PATH,
        SIGNED_CDN_AUTHORITY_PATH,
        RECOVERY_STATEMENT_PATH,
        RECOVERY_AUTHORITY_PATH,
    ]
    relative_paths.extend(path for path, _ in CONTROLLING_PLANS.values())
    for relative_path in relative_paths:
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            source = repository / relative_path
            if relative_path == RECOVERY_AUTHORITY_PATH:
                destination.write_text(
                    json.dumps(
                        build_reference_recovery_authority(),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
            else:
                destination.write_bytes(source.read_bytes())
    return root


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
    database.add_artifact(
        "run-1",
        path="reports/local/proof.json",
        sha256="b" * 64,
        size_bytes=2,
        kind="proof_receipt",
    )
    database.transition("run-1", "completed", ended_at="2026-08-21T00:00:01+00:00")
    run = database.get_run("run-1")
    assert run["status"] == "completed"
    assert run["metrics"]["proof"]["value"] is False
    assert run["artifacts"] == [
        {
            "path": "reports/local/proof.json",
            "sha256": "b" * 64,
            "size_bytes": 2,
            "kind": "proof_receipt",
        }
    ]
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
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE '%_v2'"
            ).fetchone()[0]
            == 0
        )


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
    lease_expires_at: str = "2026-08-22T00:05:00+00:00",
    started_at: str = "2026-08-22T00:00:00+00:00",
    settled_smoke_actual_usd: str | None = "0.00270969",
    standing_authority_sha256: str = REFERENCE_AUTHORITY_SHA256,
    bootstrap_authority_sha256: str = REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    standing_setup: bool = False,
    replacement_entitlement_sha256: str | None = None,
    approval_expires_at: str = "2026-08-22T01:00:00+00:00",
) -> None:
    if settled_smoke_actual_usd is not None:
        with database.connect_readonly() as connection:
            smoke_exists = connection.execute(
                "SELECT 1 FROM provider_smoke_reservations LIMIT 1"
            ).fetchone()
        if smoke_exists is None:
            _record_settled_provider_smoke(database, actual_cost_usd=settled_smoke_actual_usd)
    inputs = {
        "source_revision": "d" * 40,
        "weight_inventory_sha256": "1" * 64,
        "weight_inventory_tensor_bytes": 55,
        "provenance_manifest_sha256": "2" * 64,
        "runtime_receipt_sha256": "3" * 64,
        "evaluation_lock_sha256": "4" * 64,
        "evaluation_max_context_tokens": 262144,
        "formula_authority_sha256": "5" * 64,
        "reviewed_commit_sha256": "6" * 40,
        "control_plane_sha256": "7" * 64,
    }
    raw = {
        "schema_version": REFERENCE_CONFIG_SCHEMA_VERSION,
        "kind": "modal_reference_preview",
        "experiment_id": f"reference-{suffix}",
        "original_approved_plan_path": ORIGINAL_APPROVED_PLAN_PATH,
        "original_approved_plan_sha256": ORIGINAL_APPROVED_PLAN_SHA256,
        "approved_amendment_path": APPROVED_PROVIDER_AMENDMENT_PATH,
        "approved_amendment_sha256": APPROVED_PROVIDER_AMENDMENT_SHA256,
        "approved_trust_override_plan_path": APPROVED_TRUST_OVERRIDE_PLAN_PATH,
        "approved_trust_override_plan_sha256": APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
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
            "constraint_contract_path": "reports/local/constraint.json",
            "constraint_contract_sha256": "a" * 64,
            "observation_receipt_path": "reports/local/observation.json",
            "observation_receipt_sha256": observation_receipt_sha256,
            "observation_screenshot_sha256": "2" * 64,
            "trust_override_path": "reports/local/trust-override.json",
            "trust_override_sha256": "3" * 64,
            "human_approval_statement_sha256": APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256,
            "billing_authority_path": "reports/local/billing.json",
            "billing_authority_sha256": "c" * 64,
            "authoritative_report_identity_sha256": "1" * 64,
            "billing_completeness_delay_seconds": 3600,
        },
        "gates": {
            "architecture_metadata_path": "reports/local/architecture-metadata.json",
            "architecture_metadata_sha256": "d" * 64,
            "bound_receipt_root": "reports/local/reference-bound-receipts",
            "cold_path_method_path": "reports/local/cold-path-method.json",
            "cold_path_method_sha256": "e" * 64,
            "formula_authority_path": "reports/local/formula-authority.json",
            "formula_approval_path": "reports/local/formula-approval.json",
            "formula_approval_sha256": "8" * 64,
            "image_build_identity_path": "reports/local/image-build-identity.json",
            "image_build_identity_sha256": "f" * 64,
            "memory_fit_evidence_path": "reports/local/memory-fit-evidence.json",
            "memory_fit_evidence_sha256": "0" * 64,
            "memory_method_path": "reports/local/memory-method.json",
            "memory_method_sha256": "1" * 64,
            "cold_path_time_evidence_path": "reports/local/cold-path-evidence.json",
            "cold_path_time_evidence_sha256": "2" * 64,
        },
        "approval_artifact_path": None,
    }
    assert set(raw["gates"]) == REFERENCE_GATE_FIELDS
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
    if not standing_setup:
        database.register_reference_challenge(
            challenge_sha256=challenge,
            packet_sha256="c" * 64,
            created_at="2026-08-22T00:00:00+00:00",
        )
        if attach_approval:
            database.attach_reference_approval(
                challenge_sha256=challenge,
                approval_digest=approval,
                expires_at=approval_expires_at,
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
        total_cap_usd="4.00270969",
        single_job_cap_usd="4.00",
        idempotency_key=f"idempotency-{suffix}",
        owner_id="owner",
        lease_expires_at=lease_expires_at,
        started_at=started_at,
        challenge_sha256=challenge,
        approval_digest=approval,
        standing_authority_sha256=standing_authority_sha256,
        bootstrap_authority_sha256=bootstrap_authority_sha256,
        authority_root=_authority_root(database),
        standing_packet_sha256="c" * 64 if standing_setup else None,
        approval_expires_at=approval_expires_at if standing_setup else None,
        attempt_config_path="configs/local/reference.yaml" if standing_setup else None,
        attempt_raw_config_sha256="a" * 64 if standing_setup else None,
        replacement_entitlement_sha256=replacement_entitlement_sha256,
        recovery_authority_sha256=(
            REFERENCE_RECOVERY_AUTHORITY_SHA256
            if replacement_entitlement_sha256 is not None
            else None
        ),
    )


def _record_settled_provider_smoke(
    database: ResultsDatabase, *, actual_cost_usd: str = "0.00270969"
) -> None:
    with database.connect() as connection:
        connection.execute(
            """INSERT INTO provider_smoke_reservations(
                reservation_id, action_contract_sha256, execution_scope_sha256,
                challenge_sha256, approval_digest, contract_json, status,
                requested_cost_usd, owner_id, provider_actual_cost_usd,
                settlement_identity, created_at, updated_at
            ) VALUES (
                'settled-smoke', ?, ?, ?, ?, '{}', 'settled', '4.00', 'owner', ?, ?, ?, ?
            )""",
            (
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                actual_cost_usd,
                "5" * 64,
                "2026-08-25T00:00:00+00:00",
                "2026-08-25T01:00:00+00:00",
            ),
        )


def test_standing_reference_setup_rolls_back_with_failed_reservation(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="active")

    with pytest.raises(DatabaseError, match="exceeds phase cap"):
        _reserve(database, suffix="rolled-back", standing_setup=True)

    with database.connect_readonly() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM attempts WHERE attempt_id = 'attempt-rolled-back'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute("SELECT count(*) FROM reference_approval_challenges").fetchone()[0]
            == 1
        )


def _downgrade_v9_to_v8(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE reference_authority_slots")
        connection.execute(
            "UPDATE schema_info SET version = 8 WHERE version IN (10, 11, 12, 13, 14)"
        )


def _downgrade_v10_to_v9(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE reference_replacement_entitlements")
        connection.execute("DROP TABLE reference_preidentity_settlements")
        connection.execute("DROP TABLE reference_workspace_scope_reconciliations")
        connection.execute(
            "UPDATE schema_info SET version = 9 WHERE version IN (10, 11, 12, 13, 14)"
        )


def _submit(database: ResultsDatabase, reservation_id: str, *, lease: str) -> None:
    database.mark_reference_submission_pending(
        reservation_id,
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    database.mark_reference_provider_prepared(
        reservation_id,
        owner_id="owner",
        provider_image_identity=f"im-{reservation_id}",
        app_identity=f"app-{reservation_id}",
        occurred_at="2026-08-22T00:00:45+00:00",
        lease_expires_at="2026-08-22T00:05:00+00:00",
    )
    database.mark_reservation_submitted(
        reservation_id,
        owner_id="owner",
        provider_job_id=f"job-{reservation_id}",
        app_identity=f"app-{reservation_id}",
        occurred_at="2026-08-22T00:01:00+00:00",
        lease_expires_at=lease,
    )


def _await_settlement(database: ResultsDatabase, reservation_id: str, *, lease: str) -> None:
    database.mark_settlement_pending(
        reservation_id,
        owner_id="owner",
        occurred_at="2026-08-22T00:02:00+00:00",
        provider_terminal_at="2026-08-22T00:02:00+00:00",
        lease_expires_at=lease,
    )


def _billing_report(
    reservation_id: str, actual_cost_usd: str, *, covered_through: str = "2026-08-22T01:02:00+00:00"
) -> dict[str, str]:
    report = {
        "schema_version": 1,
        "kind": "provider_billing_report_receipt",
        "provider_job_id": f"job-{reservation_id}",
        "billing_authority_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "covered_through": covered_through,
        "actual_cost_usd": actual_cost_usd,
    }
    report_json = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "actual_cost_usd": actual_cost_usd,
        "billing_authority_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_report_json": report_json,
        "billing_report_sha256": hashlib.sha256(report_json.encode()).hexdigest(),
    }


def _billing_report_for_identity(
    provider_identity: str,
    actual_cost_usd: str,
    *,
    covered_through: str = "2026-08-22T00:46:00+00:00",
) -> dict[str, str]:
    report = {
        "schema_version": 1,
        "kind": "provider_billing_report_receipt",
        "provider_job_id": provider_identity,
        "billing_authority_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "covered_through": covered_through,
        "actual_cost_usd": actual_cost_usd,
    }
    report_json = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "actual_cost_usd": actual_cost_usd,
        "billing_authority_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_report_json": report_json,
        "billing_report_sha256": hashlib.sha256(report_json.encode()).hexdigest(),
    }


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
            DROP TABLE reference_replacement_entitlements;
            DROP TABLE reference_preidentity_settlements;
            DROP TABLE reference_workspace_scope_reconciliations;
            DROP TABLE controller_cycle_transitions;
            DROP TABLE controller_cycles;
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
        assert (
            connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            == SCHEMA_VERSION
        )
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        legacy = connection.execute(
            """SELECT reference_execution_scope_sha256, trust_override_sha256,
                billing_authority_sha256,
                authoritative_report_identity_sha256,
                billing_completeness_delay_seconds, submitted_at, settlement_pending_at
            FROM budget_reservations"""
        ).fetchone()
        actual = connection.execute("SELECT modal_cost_actual_usd FROM experiments").fetchone()[0]
    assert tuple(legacy) == (None, None, None, None, None, None, None)
    assert actual == "0"


def test_v4_to_v5_migration_rolls_back_on_unknown_schema_state(tmp_path: Path) -> None:
    path = tmp_path / "rollback.sqlite"
    _downgrade_populated_database_to_v4(path)
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE budget_reservations_v5(blocker INTEGER)")
    with pytest.raises(DatabaseError, match="v5 migration failed"):
        ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 4
        assert connection.execute("SELECT count(*) FROM experiments").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        columns = {row[1] for row in connection.execute("PRAGMA table_info(budget_reservations)")}
        assert (
            connection.execute(
                """SELECT count(*) FROM sqlite_master
                WHERE type = 'table' AND name = 'experiments_v5'"""
            ).fetchone()[0]
            == 0
        )
    assert "reference_execution_scope_sha256" not in columns


def test_reference_execution_scope_is_canonical_and_source_bound() -> None:
    scope = reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
        formula_approval_sha256="8" * 64,
    )
    assert len(scope) == 64
    assert scope == reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
        formula_approval_sha256="8" * 64,
    )
    for changed in (
        {"source_revision": "e" * 40},
        {"weight_inventory_sha256": "2" * 64},
        {"evaluation_lock_sha256": "6" * 64},
        {"formula_authority_sha256": "7" * 64},
        {"formula_approval_sha256": "9" * 64},
    ):
        inputs = {
            "source_revision": "d" * 40,
            "weight_inventory_sha256": "1" * 64,
            "evaluation_lock_sha256": "4" * 64,
            "formula_authority_sha256": "5" * 64,
            "formula_approval_sha256": "8" * 64,
        }
        inputs.update(changed)
        assert reference_execution_scope_sha256(**inputs) != scope
    assert (
        reference_execution_scope_sha256(
            source_revision="e" * 64,
            weight_inventory_sha256="1" * 64,
            evaluation_lock_sha256="4" * 64,
            formula_authority_sha256="5" * 64,
            formula_approval_sha256="8" * 64,
        )
        != scope
    )
    with pytest.raises(ValueError, match="source revision"):
        reference_execution_scope_sha256(
            source_revision="D" * 40,
            weight_inventory_sha256="1" * 64,
            evaluation_lock_sha256="4" * 64,
            formula_authority_sha256="5" * 64,
            formula_approval_sha256="8" * 64,
        )


def test_reference_reservation_is_atomic_and_prevents_cap_overlap(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="one")
    with pytest.raises(DatabaseError, match="cap|consumed"):
        _reserve(database, suffix="two")
    assert database.get_attempt("attempt-two")["status"] == "received"
    assert database.get_reservation("reservation-one")["status"] == "reserved"
    assert database.get_reservation("reservation-one")["trust_override_sha256"] == "3" * 64
    assert database.get_run("run-one")["modal_cost_actual_usd"] is None
    with database.connect() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM experiments WHERE run_id = 'run-two'"
            ).fetchone()[0]
            == 0
        )


def test_reference_requires_the_exact_authoritative_smoke_cost(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with database.connect() as connection:
        connection.execute(
            """INSERT INTO provider_smoke_reservations(
                reservation_id, action_contract_sha256, execution_scope_sha256,
                challenge_sha256, approval_digest, contract_json, status,
                requested_cost_usd, provider_actual_cost_usd, owner_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, '{}', 'settled', '4.00', '0.00', ?, ?, ?)""",
            (
                "settled-smoke",
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "smoke-owner",
                "2026-08-21T23:00:00+00:00",
                "2026-08-21T23:30:00+00:00",
            ),
        )
    with pytest.raises(DatabaseError, match="exact settled provider smoke"):
        _reserve(database, suffix="after-zero-smoke")
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


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


def _remove_gate_field(raw: dict[str, object], field: str) -> None:
    gates = raw["gates"]
    assert isinstance(gates, dict)
    gates.pop(field)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw.pop("approved_amendment_sha256"), "schema"),
        (
            lambda raw: raw.__setitem__("approved_amendment_sha256", "f" * 64),
            "authority",
        ),
        (
            lambda raw: raw.__setitem__("approved_amendment_path", "docs/plans/local/wrong.md"),
            "authority",
        ),
        (
            lambda raw: raw.__setitem__("approved_trust_override_plan_sha256", "f" * 64),
            "authority",
        ),
        (lambda raw: _remove_provider_field(raw, "constraint_contract_path"), "schema"),
        (
            lambda raw: _set_provider_field(raw, "observation_receipt_sha256", None),
            "authority",
        ),
        (lambda raw: _remove_provider_field(raw, "workspace_scope_sha256"), "schema"),
        (
            lambda raw: _set_provider_field(raw, "workspace_scope_sha256", 1),
            "provider authority",
        ),
        (
            lambda raw: _set_provider_field(raw, "constraint_contract_sha256", 1),
            "provider authority",
        ),
        (
            lambda raw: _set_provider_field(raw, "trust_override_sha256", None),
            "trust override",
        ),
        (
            lambda raw: _set_provider_field(raw, "human_approval_statement_sha256", "f" * 64),
            "human approval statement",
        ),
        (
            lambda raw: raw["inputs"].__setitem__("source_revision", 1),
            "source_revision",
        ),
        (
            lambda raw: raw["inputs"].__setitem__("weight_inventory_sha256", 1),
            "scope authority",
        ),
        (lambda raw: _remove_gate_field(raw, "bound_receipt_root"), "schema"),
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
    _submit(database, "reservation-settle", lease="2026-08-22T00:10:00+00:00")
    _await_settlement(database, "reservation-settle", lease="2026-08-22T02:10:00+00:00")
    database.settle_reservation(
        "reservation-settle",
        occurred_at="2026-08-22T01:02:00+00:00",
        **_billing_report("reservation-settle", "2.50"),
    )
    reservation = database.get_reservation("reservation-settle")
    assert reservation["status"] == "settled"
    assert reservation["provider_actual_cost_usd"] == "2.50"
    assert database.get_run("run-settle")["modal_cost_actual_usd"] == "2.50"
    with pytest.raises(DatabaseError, match="cannot settle"):
        database.settle_reservation(
            "reservation-settle",
            occurred_at="2026-08-22T01:02:01+00:00",
            **_billing_report("reservation-settle", "2.50"),
        )


def test_reference_settlement_requires_bound_complete_billing(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="billing")
    reservation = database.get_reservation("reservation-billing")
    assert reservation["billing_authority_sha256"] == "c" * 64
    assert reservation["authoritative_report_identity_sha256"] == "1" * 64
    assert reservation["billing_completeness_delay_seconds"] == 3600
    _submit(database, "reservation-billing", lease="2026-08-22T00:10:00+00:00")
    with pytest.raises(DatabaseError, match="cannot settle"):
        database.settle_reservation(
            "reservation-billing",
            occurred_at="2026-08-22T01:02:00+00:00",
            **_billing_report("reservation-billing", "1.00"),
        )
    _await_settlement(database, "reservation-billing", lease="2026-08-22T02:10:00+00:00")
    for changed, occurred_at, message in (
        (
            {"authoritative_report_identity_sha256": "2" * 64},
            "2026-08-22T01:02:00+00:00",
            "identity",
        ),
        ({"billing_authority_sha256": "d" * 64}, "2026-08-22T01:02:00+00:00", "authority"),
        ({}, "2026-08-22T01:01:59+00:00", "not yet complete"),
    ):
        billing = _billing_report("reservation-billing", "1.00")
        billing.update(changed)
        with pytest.raises(DatabaseError, match=message):
            database.settle_reservation(
                "reservation-billing",
                occurred_at=occurred_at,
                **billing,
            )
        unchanged = database.get_reservation("reservation-billing")
        assert unchanged["status"] == "settlement_pending"
        assert unchanged["provider_actual_cost_usd"] is None


def test_reference_lease_renewal_is_owner_checked_and_prevents_reconciliation(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="renew")
    with pytest.raises(DatabaseError, match="cannot renew"):
        database.renew_reservation_lease(
            "reservation-renew",
            owner_id="other",
            occurred_at="2026-08-22T00:04:00+00:00",
            lease_expires_at="2026-08-22T00:20:00+00:00",
        )
    database.renew_reservation_lease(
        "reservation-renew",
        owner_id="owner",
        occurred_at="2026-08-22T00:04:00+00:00",
        lease_expires_at="2026-08-21T20:20:00-04:00",
    )
    assert database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00") == {
        "released": [],
        "audit_blocked": [],
    }


def test_reference_lease_boundaries_fail_closed(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="lease must expire after"):
        _reserve(
            database,
            suffix="initial-expired",
            lease_expires_at="2026-08-22T00:00:00+00:00",
        )

    _reserve(database, suffix="expired")
    with pytest.raises(DatabaseError, match="lease has expired"):
        database.renew_reservation_lease(
            "reservation-expired",
            owner_id="owner",
            occurred_at="2026-08-22T00:05:01+00:00",
            lease_expires_at="2026-08-22T00:20:00+00:00",
        )
    with pytest.raises(DatabaseError, match="lease has expired"):
        database.mark_reservation_submitted(
            "reservation-expired",
            owner_id="owner",
            provider_job_id="job-expired",
            app_identity="app-expired",
            occurred_at="2026-08-22T00:05:01+00:00",
            lease_expires_at="2026-08-22T00:20:00+00:00",
        )


def test_settlement_pending_rejects_backdated_provider_terminal_time(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="backdated")
    _submit(database, "reservation-backdated", lease="2026-08-22T00:10:00+00:00")
    with pytest.raises(DatabaseError, match="provider terminal time"):
        database.mark_settlement_pending(
            "reservation-backdated",
            owner_id="owner",
            occurred_at="2026-08-22T00:03:00+00:00",
            provider_terminal_at="2026-08-22T00:00:59+00:00",
            lease_expires_at="2026-08-22T02:10:00+00:00",
        )


def test_stale_reference_reservations_release_only_before_submission(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="pre")
    released = database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert released == {"released": ["reservation-pre"], "audit_blocked": []}
    assert database.get_run("run-pre")["status"] == "failed"

    _reserve(database, suffix="post", observation_receipt_sha256="e" * 64)
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_released_precontact_reservation_preserves_u8_slot(tmp_path: Path) -> None:
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
    with database.connect() as connection:
        consumed = connection.execute(
            "SELECT count(*) FROM reference_approval_challenges WHERE consumed_at IS NOT NULL"
        ).fetchone()[0]
    assert consumed == 2


@pytest.mark.parametrize(
    "terminal", ["submitted", "settlement_pending", "settled", "audit_blocked", "failed"]
)
def test_submitted_or_later_scope_is_permanently_consumed(tmp_path: Path, terminal: str) -> None:
    database = ResultsDatabase(tmp_path / f"{terminal}.sqlite")
    database.initialize()
    _reserve(database, suffix=f"used-{terminal}")
    reservation_id = f"reservation-used-{terminal}"
    _submit(database, reservation_id, lease="2026-08-22T00:06:00+00:00")
    if terminal == "settlement_pending":
        _await_settlement(database, reservation_id, lease="2026-08-22T02:10:00+00:00")
    elif terminal == "settled":
        _await_settlement(database, reservation_id, lease="2026-08-22T02:10:00+00:00")
        database.settle_reservation(
            reservation_id,
            occurred_at="2026-08-22T01:02:00+00:00",
            **_billing_report(reservation_id, "4.00"),
        )
    elif terminal == "audit_blocked":
        database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    elif terminal == "failed":
        _await_settlement(database, reservation_id, lease="2026-08-22T02:10:00+00:00")
        with pytest.raises(DatabaseError, match="budget failure"):
            database.settle_reservation(
                reservation_id,
                occurred_at="2026-08-22T01:02:00+00:00",
                **_billing_report(reservation_id, "4.01"),
            )

    with pytest.raises(DatabaseError, match="scope"):
        _reserve(
            database,
            suffix=f"retry-{terminal}",
            observation_receipt_sha256="e" * 64,
        )


def test_concurrent_connections_cannot_reserve_the_same_scope_twice(tmp_path: Path) -> None:
    path = tmp_path / "race.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _record_settled_provider_smoke(database)

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
    _submit(database, "reservation-over", lease="2026-08-22T00:10:00+00:00")
    _await_settlement(database, "reservation-over", lease="2026-08-22T02:10:00+00:00")
    with pytest.raises(DatabaseError, match="budget failure"):
        database.settle_reservation(
            "reservation-over",
            occurred_at="2026-08-22T01:02:00+00:00",
            **_billing_report("reservation-over", "4.00000001"),
        )
    reservation = database.get_reservation("reservation-over")
    assert reservation["status"] == "failed"
    assert reservation["provider_actual_cost_usd"] == "4.00000001"
    assert (
        reservation["settlement_identity"]
        == _billing_report("reservation-over", "4.00000001")["billing_report_sha256"]
    )
    run = database.get_run("run-over")
    assert run["status"] == "failed"
    assert run["modal_cost_actual_usd"] == "4.00000001"
    with pytest.raises(DatabaseError, match="cap|consumed"):
        _reserve(
            database,
            suffix="different-scope-after-over",
            observation_receipt_sha256="e" * 64,
            mutate_config=lambda raw: raw["inputs"].__setitem__("source_revision", "e" * 40),
        )


def test_delayed_authoritative_billing_can_settle_an_audit_blocked_run(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "results.sqlite")
    database.initialize()
    _reserve(database, suffix="delayed")
    _submit(database, "reservation-delayed", lease="2026-08-22T00:06:00+00:00")
    _await_settlement(database, "reservation-delayed", lease="2026-08-22T00:07:00+00:00")
    database.reconcile_stale_reservations(now="2026-08-22T00:10:00+00:00")
    assert database.get_run("run-delayed")["modal_cost_actual_usd"] is None
    database.settle_reservation(
        "reservation-delayed",
        occurred_at="2026-08-22T01:02:00+00:00",
        **_billing_report("reservation-delayed", "4.00"),
    )
    assert database.get_reservation("reservation-delayed")["status"] == "settled"
    assert database.get_run("run-delayed")["modal_cost_actual_usd"] == "4.00"


@pytest.mark.parametrize("provider_state", ["submission_pending", "submitted"])
def test_authoritative_billing_reconciles_audit_block_before_settlement(
    tmp_path: Path, provider_state: str
) -> None:
    database = ResultsDatabase(tmp_path / f"audit-{provider_state}.sqlite")
    database.initialize()
    suffix = f"audit-{provider_state}"
    reservation_id = f"reservation-{suffix}"
    _reserve(database, suffix=suffix)
    database.mark_reference_submission_pending(
        reservation_id,
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    database.mark_reference_provider_prepared(
        reservation_id,
        owner_id="owner",
        provider_image_identity=f"im-{suffix}",
        app_identity=f"app-{suffix}",
        occurred_at="2026-08-22T00:00:45+00:00",
        lease_expires_at="2026-08-22T00:05:00+00:00",
    )
    provider_identity = f"app-{suffix}"
    if provider_state == "submitted":
        database.mark_reservation_submitted(
            reservation_id,
            owner_id="owner",
            provider_job_id=f"job-{suffix}",
            app_identity=f"app-{suffix}",
            occurred_at="2026-08-22T00:01:00+00:00",
            lease_expires_at="2026-08-22T00:10:00+00:00",
        )
        provider_identity = f"job-{suffix}"
    database.mark_reference_audit_blocked(
        reservation_id,
        owner_id="owner",
        reason="provider boundary uncertainty: test",
        occurred_at="2026-08-22T00:01:30+00:00",
    )
    incomplete_report = _billing_report_for_identity(
        provider_identity,
        "0.25",
        covered_through="2026-08-22T00:45:00+00:00",
    )
    with pytest.raises(DatabaseError, match="full action window"):
        database.reconcile_reference_audit_billing(
            reservation_id,
            billing_report_json=incomplete_report["billing_report_json"],
            billing_report_sha256=incomplete_report["billing_report_sha256"],
            occurred_at="2026-08-22T00:45:00+00:00",
        )
    report = _billing_report_for_identity(provider_identity, "0.25")
    database.reconcile_reference_audit_billing(
        reservation_id,
        billing_report_json=report["billing_report_json"],
        billing_report_sha256=report["billing_report_sha256"],
        occurred_at="2026-08-22T00:46:00+00:00",
    )
    assert database.get_reservation(reservation_id)["status"] == "audit_blocked"
    database.settle_reservation(
        reservation_id,
        occurred_at="2026-08-22T01:46:00+00:00",
        **report,
    )
    assert database.get_reservation(reservation_id)["status"] == "settled"
    assert database.get_run(f"run-{suffix}")["modal_cost_actual_usd"] == "0.25"


def test_audit_billing_reconciliation_rejects_backdated_transition(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "audit-backdated.sqlite")
    database.initialize()
    _reserve(database, suffix="audit-backdated")
    database.mark_reference_submission_pending(
        "reservation-audit-backdated",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    database.mark_reference_provider_prepared(
        "reservation-audit-backdated",
        owner_id="owner",
        provider_image_identity="im-audit-backdated",
        app_identity="app-audit-backdated",
        occurred_at="2026-08-22T00:00:45+00:00",
        lease_expires_at="2026-08-22T00:05:00+00:00",
    )
    database.mark_reference_audit_blocked(
        "reservation-audit-backdated",
        owner_id="owner",
        reason="provider boundary uncertainty: test",
        occurred_at="2026-08-22T01:00:00+00:00",
    )
    report = _billing_report_for_identity("app-audit-backdated", "0.25")
    with pytest.raises(DatabaseError, match="backdated"):
        database.reconcile_reference_audit_billing(
            "reservation-audit-backdated",
            billing_report_json=report["billing_report_json"],
            billing_report_sha256=report["billing_report_sha256"],
            occurred_at="2026-08-22T00:50:00+00:00",
        )


def test_legacy_submitted_or_later_reservation_retains_the_full_cap(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite"
    _downgrade_populated_database_to_v4(path)
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute(
            """UPDATE budget_reservations SET status = 'settled',
                provider_actual_cost_usd = '0', provider_job_id = 'legacy-job',
                app_identity = 'legacy-app', settlement_identity = 'legacy-bill'"""
        )
    database = ResultsDatabase(path)
    with pytest.raises(DatabaseError, match="no trustworthy execution scope"):
        database.initialize()


def _acquire_controller_cycle(
    database: ResultsDatabase,
    cycle_id: str,
    *,
    owner_id: str = "owner-one",
    started_at: str = "2026-08-23T12:00:00+00:00",
    lease_expires_at: str = "2026-08-23T12:05:00+00:00",
) -> int:
    return database.acquire_controller_cycle(
        cycle_id=cycle_id,
        workspace_id="workspace-one",
        owner_id=owner_id,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        started_at=started_at,
        lease_expires_at=lease_expires_at,
    )


def test_corrupt_v6_without_budget_ledger_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v6.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE schema_info (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO schema_info VALUES (6, '2026-08-23T00:00:00+00:00')")
    database = ResultsDatabase(path)
    with pytest.raises(DatabaseError, match="ledger is missing"):
        database.initialize()
    with database.connect() as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 12


def test_corrupt_v11_without_budget_ledger_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v11-missing-budget.sqlite"
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE schema_info (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO schema_info VALUES (11, '2026-08-23T00:00:00+00:00')")
    with pytest.raises(DatabaseError, match="ledger is missing"):
        ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 12
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master "
                "WHERE type='table' AND name='budget_reservations'"
            ).fetchone()[0]
            == 0
        )


def test_controller_cycle_lifecycle_commits_artifact_with_fencing(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()
    generation = _acquire_controller_cycle(database, "cycle-one")
    database.transition_controller_cycle(
        "cycle-one",
        owner_id="owner-one",
        generation=generation,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        from_state="created",
        to_state="validated",
        occurred_at="2026-08-23T12:01:00+00:00",
    )
    database.transition_controller_cycle(
        "cycle-one",
        owner_id="owner-one",
        generation=generation,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        from_state="validated",
        to_state="preparing",
        occurred_at="2026-08-23T12:02:00+00:00",
        lease_expires_at="2026-08-23T12:10:00+00:00",
    )
    database.finalize_controller_cycle(
        "cycle-one",
        owner_id="owner-one",
        generation=generation,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        from_state="preparing",
        to_state="paid_decision_required",
        occurred_at="2026-08-23T12:03:00+00:00",
        stop_reason="paid evidence remains explicitly unauthorized",
        artifact_path="reports/local/controller-cycles/cycle-one.json",
        artifact_sha256="c" * 64,
    )
    cycle = database.get_controller_cycle("cycle-one")
    assert cycle["generation"] == 1
    assert cycle["state"] == "paid_decision_required"
    assert cycle["artifact_sha256"] == "c" * 64
    assert [item["to_state"] for item in cycle["transitions"]] == [
        "created",
        "validated",
        "preparing",
        "paid_decision_required",
    ]
    assert database.get_latest_controller_cycle("workspace-one") == cycle


def test_controller_cycle_workspace_lease_prevents_contention(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()

    def acquire(suffix: str) -> tuple[str, object]:
        try:
            return suffix, _acquire_controller_cycle(
                database, f"cycle-{suffix}", owner_id=f"owner-{suffix}"
            )
        except DatabaseError as exc:
            return suffix, exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(acquire, ("one", "two")))
    assert sum(isinstance(result, int) for _, result in results) == 1
    errors = [result for _, result in results if isinstance(result, DatabaseError)]
    assert len(errors) == 1
    assert "active cycle" in str(errors[0])
    with database.connect() as connection:
        assert connection.execute("SELECT count(*) FROM controller_cycles").fetchone()[0] == 1


def test_controller_cycle_failure_is_terminal_without_fake_artifact(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()
    generation = _acquire_controller_cycle(database, "cycle-failed")
    database.transition_controller_cycle(
        "cycle-failed",
        owner_id="owner-one",
        generation=generation,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        from_state="created",
        to_state="failed",
        occurred_at="2026-08-23T12:01:00+00:00",
        stop_reason="immutable artifact write failed",
    )
    cycle = database.get_controller_cycle("cycle-failed")
    assert cycle["state"] == "failed"
    assert cycle["stop_reason"] == "immutable artifact write failed"
    assert cycle["artifact_path"] is None
    assert cycle["ended_at"] == "2026-08-23T12:01:00+00:00"


def test_controller_cycle_rejects_invalid_transition_drift_and_output(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()
    generation = _acquire_controller_cycle(database, "cycle-one")
    common = {
        "owner_id": "owner-one",
        "generation": generation,
        "context_sha256": "a" * 64,
        "authority_sha256": "b" * 64,
        "from_state": "created",
        "occurred_at": "2026-08-23T12:01:00+00:00",
    }
    with pytest.raises(DatabaseError, match="invalid controller transition"):
        database.transition_controller_cycle("cycle-one", to_state="preparing", **common)
    with pytest.raises(DatabaseError, match="lost ownership"):
        database.transition_controller_cycle(
            "cycle-one", to_state="validated", **{**common, "context_sha256": "d" * 64}
        )
    database.transition_controller_cycle("cycle-one", to_state="validated", **common)
    with pytest.raises(DatabaseError, match="cannot predate"):
        database.transition_controller_cycle(
            "cycle-one",
            owner_id="owner-one",
            generation=generation,
            context_sha256="a" * 64,
            authority_sha256="b" * 64,
            from_state="validated",
            to_state="preparing",
            occurred_at="2026-08-23T12:00:30+00:00",
        )
    database.transition_controller_cycle(
        "cycle-one",
        owner_id="owner-one",
        generation=generation,
        context_sha256="a" * 64,
        authority_sha256="b" * 64,
        from_state="validated",
        to_state="preparing",
        occurred_at="2026-08-23T12:02:00+00:00",
    )
    finalize = {
        "owner_id": "owner-one",
        "generation": generation,
        "context_sha256": "a" * 64,
        "authority_sha256": "b" * 64,
        "from_state": "preparing",
        "to_state": "stopped",
        "occurred_at": "2026-08-23T12:03:00+00:00",
        "artifact_sha256": "c" * 64,
    }
    with pytest.raises(DatabaseError, match="at most 1024"):
        database.finalize_controller_cycle(
            "cycle-one",
            stop_reason="x" * 1025,
            artifact_path="reports/local/cycle.json",
            **finalize,
        )
    with pytest.raises(DatabaseError, match="private machine path"):
        database.finalize_controller_cycle(
            "cycle-one",
            stop_reason="credential gh" + "p_" + "abcdefghijklmnopqrstuvwxyz",
            artifact_path="reports/local/cycle.json",
            **finalize,
        )
    with pytest.raises(DatabaseError, match="portable local-artifact path"):
        database.finalize_controller_cycle(
            "cycle-one",
            stop_reason="manual stop",
            artifact_path="../private/cycle.json",
            **finalize,
        )
    assert database.get_controller_cycle("cycle-one")["state"] == "preparing"


def test_expired_controller_cycle_is_fenced_reconciled_and_replaced(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()
    generation = _acquire_controller_cycle(
        database,
        "cycle-stale",
        lease_expires_at="2026-08-23T12:01:00+00:00",
    )
    with pytest.raises(DatabaseError, match="lease has expired"):
        database.transition_controller_cycle(
            "cycle-stale",
            owner_id="owner-one",
            generation=generation,
            context_sha256="a" * 64,
            authority_sha256="b" * 64,
            from_state="created",
            to_state="validated",
            occurred_at="2026-08-23T12:02:00+00:00",
        )
    assert database.reconcile_stale_controller_cycles(now="2026-08-23T12:02:00+00:00") == [
        "cycle-stale"
    ]
    stale = database.get_controller_cycle("cycle-stale")
    assert stale["state"] == "failed"
    assert stale["artifact_path"] is None
    with pytest.raises(DatabaseError, match="finalization lost ownership"):
        database.finalize_controller_cycle(
            "cycle-stale",
            owner_id="owner-one",
            generation=generation,
            context_sha256="a" * 64,
            authority_sha256="b" * 64,
            from_state="created",
            to_state="failed",
            occurred_at="2026-08-23T12:02:30+00:00",
            stop_reason="stale owner",
            artifact_path="reports/local/stale.json",
            artifact_sha256="c" * 64,
        )
    assert (
        _acquire_controller_cycle(
            database,
            "cycle-new",
            owner_id="owner-two",
            started_at="2026-08-23T12:03:00+00:00",
            lease_expires_at="2026-08-23T12:08:00+00:00",
        )
        == 2
    )


def test_controller_acquire_atomically_reconciles_expired_cycle(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "controller.sqlite")
    database.initialize()
    assert (
        _acquire_controller_cycle(
            database,
            "cycle-one",
            lease_expires_at="2026-08-23T12:01:00+00:00",
        )
        == 1
    )
    assert (
        _acquire_controller_cycle(
            database,
            "cycle-two",
            owner_id="owner-two",
            started_at="2026-08-23T12:02:00+00:00",
            lease_expires_at="2026-08-23T12:07:00+00:00",
        )
        == 2
    )
    assert database.get_controller_cycle("cycle-one")["state"] == "failed"


def test_reference_provider_boundary_atomically_consumes_u8_slot(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"
    _reserve(database, suffix="atomic")
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"
    database.mark_reference_submission_pending(
        "reservation-atomic",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    assert database.get_reservation("reservation-atomic")["status"] == "submission_pending"
    slot = database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)
    assert slot == {
        "state": "consumed",
        "execution_scope_sha256": database.get_reservation("reservation-atomic")[
            "reference_execution_scope_sha256"
        ],
        "consumed_at": "2026-08-22T00:00:30+00:00",
    }


def test_reference_provider_identity_is_durable_before_call_identity(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-prepared.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="prepared")
    database.mark_reference_submission_pending(
        "reservation-prepared",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    database.mark_reference_provider_prepared(
        "reservation-prepared",
        owner_id="owner",
        provider_image_identity="im-reference-locked",
        app_identity="ap-reference-run",
        occurred_at="2026-08-22T00:00:45+00:00",
        lease_expires_at="2026-08-22T00:10:00+00:00",
    )
    prepared = database.get_reservation("reservation-prepared")
    assert prepared["status"] == "submission_pending"
    assert prepared["provider_image_identity"] == "im-reference-locked"
    assert prepared["app_identity"] == "ap-reference-run"
    database.mark_reservation_submitted(
        "reservation-prepared",
        owner_id="owner",
        provider_job_id="fc-reference-call",
        app_identity="ap-reference-run",
        occurred_at="2026-08-22T00:01:00+00:00",
        lease_expires_at="2026-08-22T00:20:00+00:00",
    )
    assert (
        database.get_reservation("reservation-prepared")["provider_job_id"] == "fc-reference-call"
    )


def test_failed_reference_reservation_does_not_preconsume_u8_slot(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="cumulative"):
        _reserve(database, suffix="no-smoke", settled_smoke_actual_usd=None)
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_reference_reservation_revalidates_authority_files(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    authority_root = _authority_root(database)
    statement = authority_root / STATEMENT_PATH
    statement.write_bytes(statement.read_bytes() + b"\n")
    with pytest.raises(DatabaseError, match="authority files"):
        _reserve(database, suffix="drifted-authority")
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_confirmed_precontact_release_does_not_consume_u8_slot(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="precontact")
    assert database.reconcile_stale_reservations(now="2026-08-22T00:06:00+00:00") == {
        "released": ["reservation-precontact"],
        "audit_blocked": [],
    }
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_release_after_provider_boundary_never_restores_u8_slot(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="pending-contact")
    database.mark_reference_submission_pending(
        "reservation-pending-contact",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    assert database.reconcile_stale_reservations(now="2026-08-22T00:06:00+00:00") == {
        "released": [],
        "audit_blocked": ["reservation-pending-contact"],
    }
    assert database.get_reservation("reservation-pending-contact")["status"] == "audit_blocked"
    with pytest.raises(DatabaseError, match="permanently consumed|slot is already consumed"):
        _reserve(database, suffix="after-contact", observation_receipt_sha256="e" * 64)


def test_reference_submit_requires_consumed_provider_boundary(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="boundary-bypass")
    with pytest.raises(DatabaseError, match="provider-contact boundary"):
        database.mark_reservation_submitted(
            "reservation-boundary-bypass",
            owner_id="owner",
            provider_job_id="job-boundary-bypass",
            app_identity="app-boundary-bypass",
            occurred_at="2026-08-22T00:01:00+00:00",
            lease_expires_at="2026-08-22T00:10:00+00:00",
        )


@pytest.mark.parametrize("terminal_status", ["settled", "failed"])
def test_v8_migration_consumes_slot_for_zero_cost_provider_contact(
    tmp_path: Path, terminal_status: str
) -> None:
    path = tmp_path / f"v8-{terminal_status}.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix=terminal_status)
    _submit(database, f"reservation-{terminal_status}", lease="2026-08-22T00:10:00+00:00")
    with database.connect() as connection:
        if terminal_status == "settled":
            connection.execute(
                """UPDATE budget_reservations SET status = 'settled',
                    provider_actual_cost_usd = '0', settlement_identity = ?,
                    settlement_pending_at = ?, updated_at = ?
                    WHERE reservation_id = ?""",
                (
                    "d" * 64,
                    "2026-08-22T00:02:00+00:00",
                    "2026-08-22T01:02:00+00:00",
                    f"reservation-{terminal_status}",
                ),
            )
        else:
            connection.execute(
                """UPDATE budget_reservations SET status = 'failed',
                    provider_actual_cost_usd = '0', failure_reason = 'provider failure',
                    updated_at = ? WHERE reservation_id = ?""",
                ("2026-08-22T00:02:00+00:00", f"reservation-{terminal_status}"),
            )
    _downgrade_v9_to_v8(path)
    with pytest.raises(DatabaseError, match="contacted reference rows without image lineage"):
        database.initialize()


def test_v8_migration_fails_closed_for_multiple_provider_contacts(tmp_path: Path) -> None:
    path = tmp_path / "v8-ambiguous.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="history-a")
    _submit(database, "reservation-history-a", lease="2026-08-22T00:10:00+00:00")
    with database.connect() as connection:
        connection.execute(
            "UPDATE budget_reservations SET status = 'released' WHERE reservation_id = ?",
            ("reservation-history-a",),
        )
        connection.execute("DELETE FROM reference_authority_slots")
    _reserve(database, suffix="history-b", observation_receipt_sha256="e" * 64)
    _submit(database, "reservation-history-b", lease="2026-08-22T00:10:00+00:00")
    _downgrade_v9_to_v8(path)
    with pytest.raises(DatabaseError, match="multiple historical"):
        database.initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 8


def test_v9_to_v10_migration_preserves_budget_rows_and_adds_pending_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v9-budget.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="v9-preserved")
    database.mark_reference_submission_pending(
        "reservation-v9-preserved",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    before = database.get_reservation("reservation-v9-preserved")
    _downgrade_v10_to_v9(path)
    database.initialize()
    after = database.get_reservation("reservation-v9-preserved")
    assert after == before
    with database.connect_readonly() as connection:
        table_sql = connection.execute(
            """SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'budget_reservations'"""
        ).fetchone()[0]
        active_index = connection.execute(
            """SELECT sql FROM sqlite_master
            WHERE type = 'index' AND name = 'budget_reservations_active_experiment'"""
        ).fetchone()[0]
    assert "submission_pending" in table_sql
    assert "submission_pending" in active_index
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "consumed"


def test_concurrent_reference_reservations_cannot_both_acquire_u8(tmp_path: Path) -> None:
    path = tmp_path / "reference-authority-race.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _record_settled_provider_smoke(database)

    _reserve(database, suffix="race")

    def consume(_: str) -> str:
        try:
            ResultsDatabase(path).mark_reference_submission_pending(
                "reservation-race",
                owner_id="owner",
                standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
                bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
                authority_root=_authority_root(database),
                occurred_at="2026-08-22T00:00:30+00:00",
            )
        except DatabaseError as exc:
            return str(exc)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume, ("a", "b")))
    assert outcomes.count("ok") == 1
    assert sum("consumed" in outcome or "not ready" in outcome for outcome in outcomes) == 1


def test_reference_u8_slot_rejects_direct_authority_bypass(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-authority.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="standing authority"):
        _reserve(
            database,
            suffix="wrong-standing-authority",
            standing_authority_sha256="f" * 64,
        )
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"
    assert not hasattr(database, "consume_reference_u8_slot")
    with (
        database.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"),
    ):
        connection.execute(
            """INSERT INTO reference_authority_slots(
                singleton, authority_sha256, state, execution_scope_sha256, consumed_at
            ) VALUES (1, ?, 'consumed', ?, ?)""",
            ("f" * 64, "a" * 64, "2026-08-25T12:00:00+00:00"),
        )


def test_reference_reservation_rejects_bootstrap_authority_bypass(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-bootstrap-authority.sqlite")
    database.initialize()
    with pytest.raises(DatabaseError, match="bootstrap authority"):
        _reserve(
            database,
            suffix="wrong-bootstrap-authority",
            bootstrap_authority_sha256="f" * 64,
        )
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_provider_boundary_revalidates_bootstrap_statement(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-bootstrap-boundary.sqlite")
    database.initialize()
    _reserve(database, suffix="bootstrap-drift")
    authority_root = _authority_root(database)
    statement = authority_root / BOOTSTRAP_STATEMENT_PATH
    statement.write_bytes(statement.read_bytes() + b"\n")
    with pytest.raises(DatabaseError, match="bootstrap authority files"):
        database.mark_reference_submission_pending(
            "reservation-bootstrap-drift",
            owner_id="owner",
            standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
            bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            authority_root=authority_root,
            occurred_at="2026-08-22T00:00:30+00:00",
        )
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


def test_reference_total_counts_settled_smoke_but_phase_does_not(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "reference-budget.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database)
    _reserve(database, suffix="exact-total")
    assert database.get_reservation("reservation-exact-total")["requested_cost_usd"] == "4.00"


def test_reference_reservation_rejects_smoke_actual_above_exact_cumulative_cap(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "reference-budget.sqlite")
    database.initialize()
    _record_settled_provider_smoke(database, actual_cost_usd="0.00270970")
    with pytest.raises(DatabaseError, match="cumulative"):
        _reserve(database, suffix="over-total")
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "available"


_ZERO_BILLING_AUTHORITY_BYTES = json.dumps(
    {
        "attribution_method_sha256": "2" * 64,
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_completeness_delay_seconds": 3600,
        "environment_scope_sha256": "9" * 64,
        "kind": "provider_billing_authority_contract",
        "provider": "modal",
        "schema_version": 2,
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()


def _preidentity_evidence(suffix: str) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    execution_scope = reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
        formula_approval_sha256="8" * 64,
        trust_override_sha256="3" * 64,
    )
    report = CANONICAL_EMPTY_REPORT

    def auth_receipt(*, authenticated_at: str, nonce: str) -> bytes:
        value = {
            "authenticated_at": authenticated_at,
            "authenticated_workspace_identity_sha256": "7" * 64,
            "binding_sha256": "6" * 64,
            "kind": "reference_modal_workspace_auth_receipt",
            "method_sha256": AUTH_METHOD_SHA256,
            "provider": "modal",
            "original_workspace_scope_sha256": "8" * 64,
            "reconciliation_authority_sha256": _test_reconciliation_sha256(suffix),
            "schema_version": 2,
            "verification_nonce_sha256": nonce,
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    pre_auth = auth_receipt(authenticated_at="2026-08-22T01:59:00+00:00", nonce="7" * 64)
    post_auth = auth_receipt(authenticated_at="2026-08-22T01:59:30+00:00", nonce="9" * 64)
    receipt = {
        "actual_cost_usd": "0",
        "acquired_at": "2026-08-22T02:00:00+00:00",
        "all_environments": True,
        "all_resources": True,
        "authenticated_workspace_identity_sha256": "7" * 64,
        "auth_binding_sha256": "6" * 64,
        "pre_auth_receipt_sha256": hashlib.sha256(pre_auth).hexdigest(),
        "post_auth_receipt_sha256": hashlib.sha256(post_auth).hexdigest(),
        "authoritative_report_identity_sha256": "1" * 64,
        "billing_authority_sha256": hashlib.sha256(_ZERO_BILLING_AUTHORITY_BYTES).hexdigest(),
        "billing_method_sha256": "2" * 64,
        "completeness_delay_seconds": 3600,
        "currency": "USD",
        "failure_code": "auth_before_provider_identity",
        "filters": [],
        "kind": "reference_workspace_zero_billing_evidence",
        "original_execution_scope_sha256": execution_scope,
        "original_workspace_scope_sha256": "8" * 64,
        "pagination_complete": True,
        "provider": "modal",
        "query_end": "2026-08-22T01:00:00+00:00",
        "query_start": "2026-08-22T00:00:00+00:00",
        "recovery_authority_sha256": REFERENCE_RECOVERY_AUTHORITY_SHA256,
        "report_sha256": hashlib.sha256(report).hexdigest(),
        "report_size_bytes": len(report),
        "reservation_id": f"reservation-{suffix}",
        "row_count": 0,
        "schema_version": 2,
        "workspace_reconciliation_authority_sha256": _test_reconciliation_sha256(suffix),
    }
    return (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(),
        report,
        _ZERO_BILLING_AUTHORITY_BYTES,
        pre_auth,
        post_auth,
    )


def _test_reconciliation(suffix: str) -> dict[str, object]:
    execution_scope = reference_execution_scope_sha256(
        source_revision="d" * 40,
        weight_inventory_sha256="1" * 64,
        evaluation_lock_sha256="4" * 64,
        formula_authority_sha256="5" * 64,
        formula_approval_sha256="8" * 64,
        trust_override_sha256="3" * 64,
    )
    return {
        "approved_base_commit": "f" * 40,
        "authenticated_workspace_identity_sha256": "7" * 64,
        "billing_authority_sha256": hashlib.sha256(_ZERO_BILLING_AUTHORITY_BYTES).hexdigest(),
        "digest_equality_asserted": False,
        "historical_config_rewrite": False,
        "kind": "reference_modal_workspace_scope_reconciliation_authority",
        "maximum_mapping_uses": 1,
        "original_execution_scope_sha256": execution_scope,
        "original_reservation_id": f"reservation-{suffix}",
        "original_workspace_scope_sha256": "8" * 64,
        "provider": "modal",
        "replacement_action": "u8_reference_replacement_once",
        "schema_version": 1,
        "statement_sha256": "9" * 64,
    }


def _test_reconciliation_sha256(suffix: str) -> str:
    return sha256_json(_test_reconciliation(suffix))


@contextmanager
def _reconciliation_context(suffix: str):
    with (
        patch(
            "lowbit_lab.db.validate_workspace_scope_reconciliation_authority",
            return_value=_test_reconciliation(suffix),
        ),
        patch(
            "lowbit_lab.db.REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256",
            _test_reconciliation_sha256(suffix),
        ),
    ):
        yield


def _audit_block_preidentity(database: ResultsDatabase, suffix: str) -> None:
    def bind_billing(raw: dict[str, object]) -> None:
        provider = raw["provider"]
        assert isinstance(provider, dict)
        provider["billing_authority_sha256"] = hashlib.sha256(
            _ZERO_BILLING_AUTHORITY_BYTES
        ).hexdigest()

    _reserve(database, suffix=suffix, mutate_config=bind_billing)
    database.mark_reference_submission_pending(
        f"reservation-{suffix}",
        owner_id="owner",
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=_authority_root(database),
        occurred_at="2026-08-22T00:00:30+00:00",
    )
    database.mark_reference_audit_blocked(
        f"reservation-{suffix}",
        owner_id="owner",
        reason="provider boundary uncertainty: AuthError",
        occurred_at="2026-08-22T00:01:00+00:00",
    )


def _settle_preidentity(database: ResultsDatabase, suffix: str) -> str:
    receipt, report, authority, pre_auth, post_auth = _preidentity_evidence(suffix)
    with _reconciliation_context(suffix):
        return database.settle_reference_preidentity_zero(
            receipt,
            report,
            pre_auth_receipt_bytes=pre_auth,
            post_auth_receipt_bytes=post_auth,
            billing_authority_bytes=authority,
            authority_root=_authority_root(database),
            occurred_at="2026-08-22T02:00:00+00:00",
        )


def test_preidentity_zero_settlement_is_atomic_and_preserves_original_slot(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / "preidentity.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "preidentity")
    original_slot = database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)

    entitlement_sha256 = _settle_preidentity(database, "preidentity")

    reservation = database.get_reservation("reservation-preidentity")
    assert reservation["status"] == "settled"
    assert reservation["settlement_mode"] == "workspace_zero_preidentity"
    assert reservation["provider_actual_cost_usd"] == "0"
    assert reservation["provider_job_id"] is None
    assert reservation["app_identity"] is None
    assert reservation["failure_reason"] == "provider boundary uncertainty: AuthError"
    run = database.get_run("run-preidentity")
    assert run["status"] == "failed"
    assert run["failure_reason"] == "provider boundary uncertainty: AuthError"
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256) == original_slot
    entitlement = database.reference_replacement_entitlement()
    assert entitlement is not None
    assert entitlement["entitlement_sha256"] == entitlement_sha256
    assert entitlement["state"] == "available"
    assert database.spend_totals(1)[0] == "0"


def test_preidentity_zero_settlement_rejects_sentinel_provider_identity(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "preidentity-sentinel.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "sentinel")
    with database.connect() as connection:
        connection.execute(
            "UPDATE budget_reservations SET app_identity = 'preidentity-sentinel' "
            "WHERE reservation_id = 'reservation-sentinel'"
        )
    with pytest.raises(DatabaseError, match="sentinel identity"):
        _settle_preidentity(database, "sentinel")
    assert database.get_reservation("reservation-sentinel")["status"] == "audit_blocked"
    assert database.reference_replacement_entitlement() is None


def test_preidentity_transaction_revalidates_exact_report_bytes(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "preidentity-bytes.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "bytes")
    receipt, report, authority, pre_auth, post_auth = _preidentity_evidence("bytes")
    value = json.loads(receipt)
    value["report_size_bytes"] = 99
    altered_receipt = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with (
        _reconciliation_context("bytes"),
        pytest.raises(DatabaseError, match="evidence validation"),
    ):
        database.settle_reference_preidentity_zero(
            altered_receipt,
            report,
            pre_auth_receipt_bytes=pre_auth,
            post_auth_receipt_bytes=post_auth,
            billing_authority_bytes=authority,
            authority_root=_authority_root(database),
            occurred_at="2026-08-22T02:00:00+00:00",
        )
    assert database.get_reservation("reservation-bytes")["status"] == "audit_blocked"


def test_preidentity_transaction_rejects_billing_authority_drift(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "preidentity-authority.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "authority")
    receipt, report, _, pre_auth, post_auth = _preidentity_evidence("authority")
    with _reconciliation_context("authority"), pytest.raises(DatabaseError, match="authority"):
        database.settle_reference_preidentity_zero(
            receipt,
            report,
            pre_auth_receipt_bytes=pre_auth,
            post_auth_receipt_bytes=post_auth,
            billing_authority_bytes=b"{}",
            authority_root=_authority_root(database),
            occurred_at="2026-08-22T02:00:00+00:00",
        )
    assert database.get_reservation("reservation-authority")["status"] == "audit_blocked"


def test_preidentity_settlement_rolls_back_if_entitlement_insert_fails(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "preidentity-rollback.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "rollback")
    with database.connect() as connection:
        connection.execute(
            """CREATE TRIGGER reject_replacement BEFORE INSERT
            ON reference_replacement_entitlements
            BEGIN SELECT RAISE(ABORT, 'test rollback'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="test rollback"):
        _settle_preidentity(database, "rollback")
    assert database.get_reservation("reservation-rollback")["status"] == "audit_blocked"
    with database.connect_readonly() as connection:
        assert (
            connection.execute("SELECT count(*) FROM reference_preidentity_settlements").fetchone()[
                0
            ]
            == 0
        )
    assert database.reference_replacement_entitlement() is None


def test_preidentity_settlement_replay_and_race_have_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "preidentity-race.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _audit_block_preidentity(database, "race-zero")

    def settle(_: int) -> str:
        try:
            _settle_preidentity(ResultsDatabase(path), "race-zero")
        except DatabaseError as exc:
            return str(exc)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(settle, (1, 2)))
    assert outcomes.count("ok") == 1
    assert sum("audit-blocked" in item for item in outcomes) == 1
    assert database.reference_replacement_entitlement()["state"] == "available"


def test_replacement_entitlement_consumes_once_at_final_boundary(tmp_path: Path) -> None:
    path = tmp_path / "replacement.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _audit_block_preidentity(database, "replacement-original")
    entitlement_sha256 = _settle_preidentity(database, "replacement-original")
    replacement_auth_receipt_bytes = _preidentity_evidence("replacement-original")[4]
    _reserve(
        database,
        suffix="replacement-child",
        replacement_entitlement_sha256=entitlement_sha256,
        started_at="2026-08-22T02:01:00+00:00",
        lease_expires_at="2026-08-22T02:10:00+00:00",
        approval_expires_at="2026-08-22T03:00:00+00:00",
    )
    assert database.reference_replacement_entitlement()["state"] == "available"
    with database.connect_readonly() as connection:
        assert format(_committed_provider_cost(connection), "f") == "4.00270969"

    def consume(_: int) -> str:
        try:
            with _reconciliation_context("replacement-original"):
                ResultsDatabase(path).mark_reference_replacement_submission_pending(
                    "reservation-replacement-child",
                    entitlement_sha256=entitlement_sha256,
                    owner_id="owner",
                    recovery_authority_sha256=REFERENCE_RECOVERY_AUTHORITY_SHA256,
                    auth_receipt_bytes=replacement_auth_receipt_bytes,
                    auth_binding_sha256="6" * 64,
                    original_workspace_scope_sha256="8" * 64,
                    authenticated_workspace_identity_sha256="7" * 64,
                    workspace_reconciliation_authority_sha256=(
                        _test_reconciliation_sha256("replacement-original")
                    ),
                    authority_root=_authority_root(database),
                    occurred_at="2026-08-22T02:02:00+00:00",
                )
        except DatabaseError as exc:
            return str(exc)
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume, (1, 2)))
    assert outcomes.count("ok") == 1
    assert sum("not ready" in item for item in outcomes) == 1
    entitlement = database.reference_replacement_entitlement()
    assert entitlement["state"] == "consumed"
    assert entitlement["replacement_reservation_id"] == "reservation-replacement-child"
    assert database.get_reservation("reservation-replacement-child")["status"] == (
        "submission_pending"
    )
    assert database.reference_u8_slot(REFERENCE_AUTHORITY_SHA256)["state"] == "consumed"


def test_replacement_boundary_revalidates_exact_auth_receipt_bytes(tmp_path: Path) -> None:
    database = ResultsDatabase(tmp_path / "replacement-auth.sqlite")
    database.initialize()
    _audit_block_preidentity(database, "replacement-auth-original")
    entitlement_sha256 = _settle_preidentity(database, "replacement-auth-original")
    _reserve(
        database,
        suffix="replacement-auth-child",
        replacement_entitlement_sha256=entitlement_sha256,
        started_at="2026-08-22T02:01:00+00:00",
        lease_expires_at="2026-08-22T02:10:00+00:00",
        approval_expires_at="2026-08-22T03:00:00+00:00",
    )
    with (
        _reconciliation_context("replacement-auth-original"),
        pytest.raises(DatabaseError, match="auth receipt"),
    ):
        database.mark_reference_replacement_submission_pending(
            "reservation-replacement-auth-child",
            entitlement_sha256=entitlement_sha256,
            owner_id="owner",
            recovery_authority_sha256=REFERENCE_RECOVERY_AUTHORITY_SHA256,
            auth_receipt_bytes=b"{}",
            auth_binding_sha256="6" * 64,
            original_workspace_scope_sha256="8" * 64,
            authenticated_workspace_identity_sha256="7" * 64,
            workspace_reconciliation_authority_sha256=(
                _test_reconciliation_sha256("replacement-auth-original")
            ),
            authority_root=_authority_root(database),
            occurred_at="2026-08-22T02:02:00+00:00",
        )
    assert database.reference_replacement_entitlement()["state"] == "available"


def _audit_block_replacement(database: ResultsDatabase, suffix: str) -> str:
    original = f"{suffix}-original"
    child = f"{suffix}-child"
    _audit_block_preidentity(database, original)
    entitlement_sha256 = _settle_preidentity(database, original)
    auth_receipt = _preidentity_evidence(original)[4]
    def bind_billing(raw: dict[str, object]) -> None:
        provider = raw["provider"]
        assert isinstance(provider, dict)
        provider["billing_authority_sha256"] = hashlib.sha256(
            _ZERO_BILLING_AUTHORITY_BYTES
        ).hexdigest()

    _reserve(
        database,
        suffix=child,
        mutate_config=bind_billing,
        replacement_entitlement_sha256=entitlement_sha256,
        started_at="2026-08-22T02:01:00+00:00",
        lease_expires_at="2026-08-22T02:10:00+00:00",
        approval_expires_at="2026-08-22T03:00:00+00:00",
    )
    with _reconciliation_context(original):
        database.mark_reference_replacement_submission_pending(
            f"reservation-{child}",
            entitlement_sha256=entitlement_sha256,
            owner_id="owner",
            recovery_authority_sha256=REFERENCE_RECOVERY_AUTHORITY_SHA256,
            auth_receipt_bytes=auth_receipt,
            auth_binding_sha256="6" * 64,
            original_workspace_scope_sha256="8" * 64,
            authenticated_workspace_identity_sha256="7" * 64,
            workspace_reconciliation_authority_sha256=_test_reconciliation_sha256(original),
            authority_root=_authority_root(database),
            occurred_at="2026-08-22T02:02:00+00:00",
        )
    database.mark_reference_audit_blocked(
        f"reservation-{child}",
        owner_id="owner",
        reason="provider boundary uncertainty: InvalidError",
        occurred_at="2026-08-22T02:03:00+00:00",
    )
    return entitlement_sha256


def _replacement_billing_evidence(
    suffix: str, entitlement_sha256: str, actual: str
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    app_id = "ap-" + "A" * 22
    original = f"{suffix}-original"
    child = f"{suffix}-child"

    def auth(nonce: str) -> bytes:
        return json.dumps(
            {
                "authenticated_at": "2026-08-22T04:00:30+00:00",
                "authenticated_workspace_identity_sha256": "7" * 64,
                "binding_sha256": "6" * 64,
                "kind": "reference_modal_workspace_auth_receipt",
                "method_sha256": AUTH_METHOD_SHA256,
                "original_workspace_scope_sha256": "8" * 64,
                "provider": "modal",
                "reconciliation_authority_sha256": _test_reconciliation_sha256(original),
                "schema_version": 2,
                "verification_nonce_sha256": nonce * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    pre, post = auth("a"), auth("b")
    app = json.dumps(
        {
            "app_id": app_id,
            "created_at": "2026-08-22T02:02:20+00:00",
            "kind": "reference_replacement_stopped_app_evidence",
            "schema_version": 1,
            "state": "stopped",
            "stopped_at": "2026-08-22T02:03:30+00:00",
            "running_tasks": 0,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    report = json.dumps(
        {
            "kind": "reference_replacement_filtered_billing_report",
            "rows": [
                {
                    "cost": actual,
                    "interval_start": "2026-08-22T02:00:00+00:00",
                    "object_id": app_id,
                    "resource": "cpu",
                }
            ],
            "schema_version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    receipt = json.dumps(
        {
            "acquired_at": "2026-08-22T04:01:00+00:00",
            "actual_cost_usd": actual,
            "app_evidence_sha256": hashlib.sha256(app).hexdigest(),
            "authenticated_workspace_identity_sha256": "7" * 64,
            "auth_binding_sha256": "6" * 64,
            "authoritative_report_identity_sha256": "1" * 64,
            "billing_authority_sha256": hashlib.sha256(
                _ZERO_BILLING_AUTHORITY_BYTES
            ).hexdigest(),
            "billing_method_sha256": "2" * 64,
            "completeness_delay_seconds": 3600,
            "entitlement_sha256": entitlement_sha256,
            "environment_scope_sha256": "9" * 64,
            "execution_scope_sha256": _test_reconciliation(original)[
                "original_execution_scope_sha256"
            ],
            "filtered_report_sha256": hashlib.sha256(report).hexdigest(),
            "filtered_report_size_bytes": len(report),
            "kind": "reference_replacement_billing_settlement",
            "post_auth_receipt_sha256": hashlib.sha256(post).hexdigest(),
            "pre_auth_receipt_sha256": hashlib.sha256(pre).hexdigest(),
            "provider": "modal",
            "query_end": "2026-08-22T03:00:00+00:00",
            "query_start": "2026-08-22T02:00:00+00:00",
            "reservation_id": f"reservation-{child}",
            "schema_version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return receipt, app, report, pre, post


@pytest.mark.parametrize(
    ("actual", "over_cap"), [("0", False), ("0.01", False), ("4.01", True)]
)
def test_replacement_billing_settlement_is_atomic_and_records_exact_cost(
    tmp_path: Path, actual: str, over_cap: bool
) -> None:
    suffix = f"billing-{'over' if over_cap else 'within'}"
    database = ResultsDatabase(tmp_path / f"{suffix}.sqlite")
    database.initialize()
    entitlement = _audit_block_replacement(database, suffix)
    receipt, app, report, pre, post = _replacement_billing_evidence(
        suffix, entitlement, actual
    )
    def call() -> str:
        return database.settle_reference_replacement_billing(
            receipt,
            app,
            report,
            pre_auth_receipt_bytes=pre,
            post_auth_receipt_bytes=post,
            billing_authority_bytes=_ZERO_BILLING_AUTHORITY_BYTES,
            occurred_at="2026-08-22T04:01:01+00:00",
        )
    if over_cap:
        with pytest.raises(DatabaseError, match="budget failure"):
            call()
    else:
        assert call() == hashlib.sha256(receipt).hexdigest()
    reservation = database.get_reservation(f"reservation-{suffix}-child")
    assert reservation["status"] == "failed"
    assert reservation["provider_actual_cost_usd"] == actual
    assert reservation["app_identity"] == "ap-" + "A" * 22
    with pytest.raises(DatabaseError):
        call()


def test_replacement_billing_settlement_rejects_inconsistent_run_state(tmp_path: Path) -> None:
    suffix = "billing-completed"
    database = ResultsDatabase(tmp_path / f"{suffix}.sqlite")
    database.initialize()
    entitlement = _audit_block_replacement(database, suffix)
    receipt, app, report, pre, post = _replacement_billing_evidence(
        suffix, entitlement, "0.01"
    )
    reservation_id = f"reservation-{suffix}-child"
    with database.connect() as connection:
        connection.execute(
            """UPDATE experiments SET status = 'completed', ended_at = ?,
                modal_cost_actual_usd = '0' WHERE run_id = ?""",
            ("2026-08-22T03:30:00+00:00", f"run-{suffix}-child"),
        )

    with pytest.raises(DatabaseError, match="run state"):
        database.settle_reference_replacement_billing(
            receipt,
            app,
            report,
            pre_auth_receipt_bytes=pre,
            post_auth_receipt_bytes=post,
            billing_authority_bytes=_ZERO_BILLING_AUTHORITY_BYTES,
            occurred_at="2026-08-22T04:01:01+00:00",
        )

    reservation = database.get_reservation(reservation_id)
    assert reservation["status"] == "audit_blocked"
    assert reservation["provider_actual_cost_usd"] is None
    with database.connect_readonly() as connection:
        transitions = connection.execute(
            "SELECT COUNT(*) FROM state_transitions WHERE run_id = ? AND to_state = 'failed'",
            (f"run-{suffix}-child",),
        ).fetchone()[0]
    assert transitions == 0


def test_replacement_billing_settlement_binds_environment_scope(tmp_path: Path) -> None:
    suffix = "billing-environment"
    database = ResultsDatabase(tmp_path / f"{suffix}.sqlite")
    database.initialize()
    entitlement = _audit_block_replacement(database, suffix)
    receipt, app, report, pre, post = _replacement_billing_evidence(
        suffix, entitlement, "0.01"
    )
    run_id = f"run-{suffix}-child"
    with database.connect() as connection:
        config_json = connection.execute(
            "SELECT config_json FROM experiments WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        config = json.loads(config_json)
        config["provider"]["environment_scope_sha256"] = "8" * 64
        connection.execute(
            "UPDATE experiments SET config_json = ? WHERE run_id = ?",
            (json.dumps(config, sort_keys=True, separators=(",", ":")), run_id),
        )

    with pytest.raises(DatabaseError, match="environment scope"):
        database.settle_reference_replacement_billing(
            receipt,
            app,
            report,
            pre_auth_receipt_bytes=pre,
            post_auth_receipt_bytes=post,
            billing_authority_bytes=_ZERO_BILLING_AUTHORITY_BYTES,
            occurred_at="2026-08-22T04:01:01+00:00",
        )

    reservation = database.get_reservation(f"reservation-{suffix}-child")
    assert reservation["status"] == "audit_blocked"
    assert reservation["provider_actual_cost_usd"] is None


def test_v12_to_v13_migration_preserves_rows_and_adds_recovery_tables(tmp_path: Path) -> None:
    path = tmp_path / "v12.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    _reserve(database, suffix="v12-preserved")
    with database.connect() as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE reference_replacement_entitlements")
        connection.execute("DROP TABLE reference_preidentity_settlements")
        connection.execute("DROP TABLE reference_workspace_scope_reconciliations")
        connection.execute("DROP INDEX budget_reservations_active_experiment")
        connection.execute("DROP INDEX budget_reservations_reference_scope")
        connection.execute("ALTER TABLE budget_reservations RENAME TO budget_reservations_v13")
        connection.execute(
            """CREATE TABLE budget_reservations (
                reservation_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES experiments(run_id) ON DELETE RESTRICT,
                experiment_id TEXT NOT NULL,
                reference_execution_scope_sha256 TEXT
                    CHECK(reference_execution_scope_sha256 IS NULL
                          OR length(reference_execution_scope_sha256) = 64),
                trust_override_sha256 TEXT
                    CHECK(trust_override_sha256 IS NULL OR length(trust_override_sha256) = 64),
                phase INTEGER NOT NULL CHECK(phase = 1),
                status TEXT NOT NULL CHECK(status IN (
                    'reserved', 'submission_pending', 'submitted', 'settlement_pending',
                    'settled', 'released', 'failed', 'audit_blocked'
                )),
                requested_cost_usd TEXT NOT NULL,
                provider_actual_cost_usd TEXT,
                provider_job_id TEXT UNIQUE,
                app_identity TEXT,
                provider_image_identity TEXT,
                billing_authority_sha256 TEXT,
                authoritative_report_identity_sha256 TEXT,
                billing_completeness_delay_seconds INTEGER,
                submitted_at TEXT,
                settlement_pending_at TEXT,
                idempotency_key TEXT NOT NULL UNIQUE,
                settlement_identity TEXT UNIQUE,
                owner_id TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
                       AND settlement_identity IS NOT NULL) OR status != 'settled'),
                CHECK((status IN ('submitted', 'settlement_pending', 'settled')
                       AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                      OR status NOT IN ('submitted', 'settlement_pending', 'settled')),
                CHECK(reference_execution_scope_sha256 IS NULL
                      OR (provider_job_id IS NULL AND submitted_at IS NULL)
                      OR provider_image_identity IS NOT NULL),
                CHECK(reference_execution_scope_sha256 IS NULL OR
                      (billing_authority_sha256 IS NOT NULL
                       AND authoritative_report_identity_sha256 IS NOT NULL
                       AND billing_completeness_delay_seconds > 0)),
                CHECK(reference_execution_scope_sha256 IS NULL
                      OR status NOT IN ('submitted', 'settlement_pending', 'settled')
                      OR submitted_at IS NOT NULL),
                CHECK(reference_execution_scope_sha256 IS NULL
                      OR status NOT IN ('settlement_pending', 'settled')
                      OR settlement_pending_at IS NOT NULL)
            )"""
        )
        v12_columns = (
            "reservation_id, run_id, experiment_id, reference_execution_scope_sha256, "
            "trust_override_sha256, phase, status, requested_cost_usd, "
            "provider_actual_cost_usd, provider_job_id, app_identity, "
            "provider_image_identity, billing_authority_sha256, "
            "authoritative_report_identity_sha256, billing_completeness_delay_seconds, "
            "submitted_at, settlement_pending_at, idempotency_key, settlement_identity, "
            "owner_id, lease_expires_at, heartbeat_at, failure_reason, created_at, updated_at"
        )
        connection.execute(
            f"INSERT INTO budget_reservations ({v12_columns}) "
            f"SELECT {v12_columns} FROM budget_reservations_v13"
        )
        connection.execute("DROP TABLE budget_reservations_v13")
        connection.execute(
            """CREATE UNIQUE INDEX budget_reservations_active_experiment
            ON budget_reservations(experiment_id)
            WHERE status IN (
                'reserved', 'submission_pending', 'submitted', 'settlement_pending',
                'audit_blocked'
            )"""
        )
        connection.execute(
            """CREATE INDEX budget_reservations_reference_scope
            ON budget_reservations(reference_execution_scope_sha256, status)"""
        )
        connection.execute(
            """CREATE TRIGGER reference_provider_image_insert
            BEFORE INSERT ON budget_reservations
            WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
             AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
             AND NEW.provider_image_identity IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'reference provider image identity required');
            END"""
        )
        connection.execute(
            """CREATE TRIGGER reference_provider_image_update
            BEFORE UPDATE ON budget_reservations
            WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
             AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
             AND NEW.provider_image_identity IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'reference provider image identity required');
            END"""
        )
        connection.execute("DELETE FROM schema_info WHERE version >= 13")
        connection.execute(
            "INSERT INTO schema_info(version, applied_at) VALUES (12, '2026-08-26T00:00:00Z')"
        )
    ResultsDatabase(path).initialize()
    with ResultsDatabase(path).connect_readonly() as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 14
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            connection.execute("SELECT count(*) FROM provider_smoke_reservations").fetchone()[0]
            == 1
        )
        assert connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0] == 1
        tables = {
            row[0]
            for row in connection.execute(
                """SELECT name FROM sqlite_master WHERE type = 'table'
                AND name IN (
                    'reference_preidentity_settlements',
                    'reference_replacement_entitlements',
                    'reference_workspace_scope_reconciliations'
                )"""
            )
        }
        columns = {row[1] for row in connection.execute("PRAGMA table_info(budget_reservations)")}
    assert tables == {
        "reference_preidentity_settlements",
        "reference_replacement_entitlements",
        "reference_workspace_scope_reconciliations",
    }
    assert "settlement_mode" in columns


def test_v12_migration_rejects_unknown_schema_before_ddl(tmp_path: Path) -> None:
    path = tmp_path / "unknown-v12.sqlite"
    database = ResultsDatabase(path)
    database.initialize()
    with database.connect() as connection:
        connection.execute("DELETE FROM schema_info WHERE version >= 13")
        connection.execute(
            "INSERT INTO schema_info(version, applied_at) VALUES (12, '2026-08-26T00:00:00Z')"
        )
    with pytest.raises(DatabaseError, match="shape is unknown"):
        ResultsDatabase(path).initialize()
    with ResultsDatabase(path).connect_readonly() as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 12
        assert "settlement_mode" in {
            row[1] for row in connection.execute("PRAGMA table_info(budget_reservations)")
        }


def test_v13_migration_rejects_unknown_empty_recovery_tables_before_ddl(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unknown-v13.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE schema_info(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO schema_info VALUES (13, '2026-08-27T00:00:00Z')")
        connection.execute("CREATE TABLE reference_preidentity_settlements(bogus TEXT)")
        connection.execute("CREATE TABLE reference_replacement_entitlements(bogus TEXT)")
    with pytest.raises(DatabaseError, match="recovery table shape is unknown"):
        ResultsDatabase(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_info").fetchone()[0] == 13
        assert connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'reference_preidentity_settlements'"
        ).fetchone()[0] == "CREATE TABLE reference_preidentity_settlements(bogus TEXT)"
