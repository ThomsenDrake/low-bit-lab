from __future__ import annotations

import argparse
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from lowbit_lab.jsonio import emit

SCHEMA_VERSION = 3
TERMINAL_STATES = {"completed", "failed"}
TRANSITIONS = {
    "created": {"validated", "failed"},
    "validated": {"running", "failed"},
    "running": TERMINAL_STATES,
    "completed": set(),
    "failed": set(),
}

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS experiment_configs (
    experiment_id TEXT PRIMARY KEY,
    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS experiments (
    run_id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
    config_json TEXT NOT NULL,
    source_hashes_json TEXT NOT NULL,
    runtime_json TEXT NOT NULL,
    hardware_json TEXT NOT NULL,
    phase INTEGER NOT NULL CHECK(phase >= 0),
    mode TEXT NOT NULL CHECK(mode IN ('local_dry_run', 'modal_dry_run', 'local_activation')),
    status TEXT NOT NULL CHECK(
        status IN ('created', 'validated', 'running', 'completed', 'failed')
    ),
    modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
    modal_cost_actual_usd TEXT NOT NULL DEFAULT '0',
    failure_reason TEXT,
    owner_id TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
);
CREATE INDEX IF NOT EXISTS experiments_config_sha ON experiments(config_sha256);
CREATE TABLE IF NOT EXISTS state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT,
    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS metrics (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    unit TEXT,
    PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS artifacts (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    kind TEXT NOT NULL,
    PRIMARY KEY (run_id, path)
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    config_path TEXT NOT NULL,
    raw_config_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('received', 'linked', 'failed')),
    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
    failure_reason TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    CHECK((status = 'received' AND ended_at IS NULL) OR
          (status IN ('linked', 'failed') AND ended_at IS NOT NULL)),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
);
CREATE TABLE IF NOT EXISTS activation_gates (
    gate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    gate_order INTEGER NOT NULL CHECK(gate_order >= 0),
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('created', 'running', 'completed', 'failed')),
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
    authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
    evidence_sha256 TEXT CHECK(evidence_sha256 IS NULL OR length(evidence_sha256) = 64),
    evidence_json TEXT,
    reused_gate_id TEXT REFERENCES activation_gates(gate_id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    failure_reason TEXT,
    evidence_valid INTEGER NOT NULL DEFAULT 1 CHECK(evidence_valid IN (0, 1)),
    invalidated_at TEXT,
    invalidation_reason TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE(run_id, gate_order),
    UNIQUE(run_id, name),
    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
    CHECK((status = 'completed' AND evidence_sha256 IS NOT NULL AND evidence_json IS NOT NULL)
          OR status != 'completed'),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed'),
    CHECK((evidence_valid = 0 AND invalidated_at IS NOT NULL AND invalidation_reason IS NOT NULL)
          OR evidence_valid = 1)
);
CREATE INDEX IF NOT EXISTS activation_gates_reuse
ON activation_gates(name, input_sha256, authority_sha256, status, evidence_valid);
"""

EVIDENCE_TABLES = (
    "experiment_configs",
    "experiments",
    "state_transitions",
    "metrics",
    "artifacts",
    "attempts",
)

V2_REPLACEMENT_SCHEMA = (
    """CREATE TABLE experiment_configs_v2 (
        experiment_id TEXT PRIMARY KEY,
        config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
        config_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )""",
    """CREATE TABLE experiments_v2 (
        run_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL
            REFERENCES experiment_configs_v2(experiment_id) ON DELETE RESTRICT,
        config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
        config_json TEXT NOT NULL,
        source_hashes_json TEXT NOT NULL,
        runtime_json TEXT NOT NULL,
        hardware_json TEXT NOT NULL,
        phase INTEGER NOT NULL CHECK(phase >= 0),
        mode TEXT NOT NULL CHECK(
            mode IN ('local_dry_run', 'modal_dry_run', 'local_activation')
        ),
        status TEXT NOT NULL CHECK(
            status IN ('created', 'validated', 'running', 'completed', 'failed')
        ),
        modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
        modal_cost_actual_usd TEXT NOT NULL DEFAULT '0',
        failure_reason TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
              (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
        CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
    )""",
    """CREATE TABLE state_transitions_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        from_state TEXT,
        to_state TEXT NOT NULL,
        reason TEXT,
        occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )""",
    """CREATE TABLE metrics_v2 (
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        name TEXT NOT NULL,
        value_json TEXT NOT NULL,
        unit TEXT,
        PRIMARY KEY (run_id, name)
    )""",
    """CREATE TABLE artifacts_v2 (
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
        kind TEXT NOT NULL,
        PRIMARY KEY (run_id, path)
    )""",
    """CREATE TABLE attempts_v2 (
        attempt_id TEXT PRIMARY KEY,
        config_path TEXT NOT NULL,
        raw_config_sha256 TEXT,
        status TEXT NOT NULL CHECK(status IN ('received', 'linked', 'failed')),
        run_id TEXT REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        failure_reason TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        CHECK((status = 'received' AND ended_at IS NULL) OR
              (status IN ('linked', 'failed') AND ended_at IS NOT NULL)),
        CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
    )""",
)

V2_COPY_COLUMNS = {
    "experiment_configs": "experiment_id, config_sha256, config_json, created_at",
    "experiments": (
        "run_id, experiment_id, config_sha256, config_json, source_hashes_json, "
        "runtime_json, hardware_json, phase, mode, status, modal_cost_requested_usd, "
        "modal_cost_actual_usd, failure_reason, started_at, ended_at"
    ),
    "state_transitions": "id, run_id, from_state, to_state, reason, occurred_at",
    "metrics": "run_id, name, value_json, unit",
    "artifacts": "run_id, path, sha256, size_bytes, kind",
    "attempts": (
        "attempt_id, config_path, raw_config_sha256, status, run_id, failure_reason, "
        "started_at, ended_at"
    ),
}


class DatabaseError(RuntimeError):
    pass


def _validate_activation_run_config(config_json: str, requested_cost: str) -> None:
    try:
        config = json.loads(config_json)
        requested = Decimal(requested_cost)
        configured_requested = Decimal(config["modal"]["requested_cost_usd"])
    except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
        raise DatabaseError("local_activation run requires complete canonical config") from exc
    if not requested.is_finite() or requested != 0 or configured_requested != 0:
        raise DatabaseError("local_activation run cost must remain zero")
    target = config.get("target")
    activation = config.get("activation")
    if (
        config.get("mode") != "local_activation"
        or config.get("weights_required") is not False
        or not isinstance(target, dict)
        or target.get("status") != "configured"
        or not isinstance(target.get("identifier"), str)
        or not target["identifier"].strip()
        or not isinstance(target.get("revision"), str)
        or re.fullmatch(r"[0-9a-f]{40,64}", target["revision"]) is None
        or not isinstance(target.get("license"), str)
        or not target["license"].strip()
        or not isinstance(activation, dict)
        or activation.get("preview_only") is not False
        or activation.get("scheduling_enabled") is not False
        or activation.get("destructive_cleanup_enabled") is not False
        or config.get("privacy", {}).get("allow_cloud_upload") is not False
        or config["modal"].get("submit") is not False
        or config["modal"].get("gpu_type") != "none"
        or config["modal"].get("gpu_count") != 0
        or config["modal"].get("cleanup") != "retain"
    ):
        raise DatabaseError("local_activation config is not executable")
    for name in (
        "approved_plan_sha256",
        "runtime_decision_sha256",
        "runtime_lock_sha256",
        "metadata_policy_sha256",
        "evaluation_lock_sha256",
    ):
        value = activation.get(name)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise DatabaseError("local_activation config authority hashes are incomplete")


def confine_results_db(root: Path, path: Path) -> Path:
    root = root.resolve()
    results_root = (root / "results").resolve()
    if not results_root.is_relative_to(root):
        raise DatabaseError("results directory resolves outside repository")
    candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not candidate.is_relative_to(results_root):
        raise DatabaseError("database path must resolve under repository results/")
    return candidate


class ResultsDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            has_schema = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_info'"
            ).fetchone()
            if has_schema is None:
                connection.executescript(SCHEMA)
                connection.execute(
                    """INSERT INTO schema_info(version, applied_at)
                    VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                    (SCHEMA_VERSION,),
                )
                return
            existing = connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            if existing == 1:
                self._migrate_v1_to_v2(connection)
                existing = 2
            if existing == 2:
                self._migrate_v2_to_v3(connection)
            elif existing != SCHEMA_VERSION:
                raise DatabaseError(f"database schema {existing} != supported {SCHEMA_VERSION}")

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            for statement in V2_REPLACEMENT_SCHEMA:
                connection.execute(statement)
            for table in EVIDENCE_TABLES:
                columns = V2_COPY_COLUMNS[table]
                connection.execute(
                    f"INSERT INTO {table}_v2 ({columns}) SELECT {columns} FROM {table}"
                )
            after_copy = {
                table: connection.execute(f"SELECT count(*) FROM {table}_v2").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after_copy:
                raise DatabaseError("schema migration row-count validation failed")
            for table in EVIDENCE_TABLES:
                if connection.execute(f"PRAGMA foreign_key_check('{table}_v2')").fetchall():
                    raise DatabaseError("schema migration foreign-key validation failed")

            for table in reversed(EVIDENCE_TABLES):
                connection.execute(f"DROP TABLE {table}")
            for table in EVIDENCE_TABLES:
                connection.execute(f"ALTER TABLE {table}_v2 RENAME TO {table}")
            connection.execute(
                "CREATE INDEX experiments_config_sha ON experiments(config_sha256)"
            )
            after_swap = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after_swap or connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema migration final validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                (2,),
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            connection.execute("ALTER TABLE experiments ADD COLUMN owner_id TEXT")
            connection.execute("ALTER TABLE experiments ADD COLUMN lease_expires_at TEXT")
            connection.execute("ALTER TABLE experiments ADD COLUMN heartbeat_at TEXT")
            connection.execute(
                """CREATE TABLE activation_gates (
                    gate_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    gate_order INTEGER NOT NULL CHECK(gate_order >= 0),
                    name TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('created', 'running', 'completed', 'failed')),
                    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
                    authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
                    evidence_sha256 TEXT
                        CHECK(evidence_sha256 IS NULL OR length(evidence_sha256) = 64),
                    evidence_json TEXT,
                    reused_gate_id TEXT
                        REFERENCES activation_gates(gate_id) ON DELETE RESTRICT,
                    owner_id TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    failure_reason TEXT,
                    evidence_valid INTEGER NOT NULL DEFAULT 1
                        CHECK(evidence_valid IN (0, 1)),
                    invalidated_at TEXT,
                    invalidation_reason TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    UNIQUE(run_id, gate_order),
                    UNIQUE(run_id, name),
                    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
                          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
                    CHECK((status = 'completed' AND evidence_sha256 IS NOT NULL
                           AND evidence_json IS NOT NULL) OR status != 'completed'),
                    CHECK((status = 'failed' AND failure_reason IS NOT NULL)
                          OR status != 'failed'),
                    CHECK((evidence_valid = 0 AND invalidated_at IS NOT NULL
                           AND invalidation_reason IS NOT NULL) OR evidence_valid = 1)
                )"""
            )
            connection.execute(
                """CREATE INDEX activation_gates_reuse
                ON activation_gates(
                    name, input_sha256, authority_sha256, status, evidence_valid
                )"""
            )
            after = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after or connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v3 migration validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                (SCHEMA_VERSION,),
            )
        except Exception as exc:
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v3 migration failed: {exc}") from exc

    def create_run(
        self,
        *,
        run_id: str,
        experiment_id: str,
        config_sha256: str,
        config_json: str,
        source_hashes: dict[str, str],
        runtime: dict[str, Any],
        hardware: dict[str, Any],
        phase: int,
        mode: str,
        requested_cost: str,
        started_at: str,
        owner_id: str | None = None,
        lease_expires_at: str | None = None,
        heartbeat_at: str | None = None,
        attempt_id: str | None = None,
    ) -> None:
        if mode == "local_activation":
            _validate_activation_run_config(config_json, requested_cost)
        with self.connect() as connection:
            registered = connection.execute(
                "SELECT config_sha256, config_json FROM experiment_configs WHERE experiment_id = ?",
                (experiment_id,),
            ).fetchone()
            if registered is None:
                connection.execute(
                    """INSERT INTO experiment_configs(experiment_id, config_sha256, config_json)
                    VALUES (?, ?, ?)""",
                    (experiment_id, config_sha256, config_json),
                )
            elif (
                registered["config_sha256"] != config_sha256
                or registered["config_json"] != config_json
            ):
                raise DatabaseError(
                    f"experiment_id is already bound to a different config: {experiment_id}"
                )
            connection.execute(
                """INSERT INTO experiments(
                    run_id, experiment_id, config_sha256, config_json, source_hashes_json,
                    runtime_json, hardware_json, phase, mode, status,
                    modal_cost_requested_usd, modal_cost_actual_usd, owner_id,
                    lease_expires_at, heartbeat_at, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, '0', ?, ?, ?, ?)""",
                (
                    run_id,
                    experiment_id,
                    config_sha256,
                    config_json,
                    json.dumps(source_hashes, sort_keys=True, separators=(",", ":")),
                    json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                    json.dumps(hardware, sort_keys=True, separators=(",", ":")),
                    phase,
                    mode,
                    requested_cost,
                    owner_id,
                    lease_expires_at,
                    heartbeat_at,
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state)
                VALUES (?, NULL, 'created')""",
                (run_id,),
            )
            if attempt_id is not None:
                cursor = connection.execute(
                    """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                    WHERE attempt_id = ? AND status = 'received'""",
                    (run_id, started_at, attempt_id),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError(f"attempt cannot be linked: {attempt_id}")

    def create_activation_gates(
        self,
        *,
        run_id: str,
        owner_id: str,
        lease_expires_at: str,
        heartbeat_at: str,
        started_at: str,
        gates: list[dict[str, Any]],
    ) -> None:
        if not owner_id or not gates:
            raise DatabaseError("activation gates require an owner and a non-empty plan")
        with self.connect() as connection:
            parent = connection.execute(
                "SELECT mode, status, owner_id FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if (
                parent is None
                or parent["mode"] != "local_activation"
                or parent["status"] in TERMINAL_STATES
                or parent["owner_id"] != owner_id
            ):
                raise DatabaseError("activation gate parent is not owned and active")
            for order, gate in enumerate(gates):
                connection.execute(
                    """INSERT INTO activation_gates(
                        gate_id, run_id, gate_order, name, status, input_sha256,
                        authority_sha256, owner_id, lease_expires_at, heartbeat_at, started_at
                    ) VALUES (?, ?, ?, ?, 'created', ?, ?, ?, ?, ?, ?)""",
                    (
                        gate["gate_id"],
                        run_id,
                        order,
                        gate["name"],
                        gate["input_sha256"],
                        gate["authority_sha256"],
                        owner_id,
                        lease_expires_at,
                        heartbeat_at,
                        started_at,
                    ),
                )

    def start_activation_gate(
        self, gate_id: str, *, owner_id: str, heartbeat_at: str, lease_expires_at: str
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'running', heartbeat_at = ?, lease_expires_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status = 'created'""",
                (heartbeat_at, lease_expires_at, gate_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot start: {gate_id}")
            run_id = connection.execute(
                "SELECT run_id FROM activation_gates WHERE gate_id = ?", (gate_id,)
            ).fetchone()[0]
            connection.execute(
                """UPDATE experiments SET heartbeat_at = ?, lease_expires_at = ?
                WHERE run_id = ? AND owner_id = ?""",
                (heartbeat_at, lease_expires_at, run_id, owner_id),
            )

    def complete_activation_gate(
        self,
        gate_id: str,
        *,
        owner_id: str,
        evidence_json: str,
        evidence_sha256: str,
        ended_at: str,
        reused_gate_id: str | None = None,
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'completed', evidence_json = ?, evidence_sha256 = ?,
                    reused_gate_id = ?, ended_at = ?, heartbeat_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (
                    evidence_json,
                    evidence_sha256,
                    reused_gate_id,
                    ended_at,
                    ended_at,
                    gate_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot complete: {gate_id}")

    def fail_activation_gate(
        self, gate_id: str, *, owner_id: str, reason: str, ended_at: str
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'failed', failure_reason = ?, ended_at = ?, heartbeat_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (reason, ended_at, ended_at, gate_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot fail: {gate_id}")

    def fail_remaining_activation_gates(
        self, run_id: str, *, owner_id: str, reason: str, ended_at: str
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """UPDATE activation_gates
                SET status = 'failed', failure_reason = ?, ended_at = ?, heartbeat_at = ?
                WHERE run_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (reason, ended_at, ended_at, run_id, owner_id),
            )

    def find_reusable_activation_gate(
        self, *, name: str, input_sha256: str, authority_sha256: str
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT * FROM activation_gates
                WHERE name = ? AND input_sha256 = ? AND authority_sha256 = ?
                  AND status = 'completed' AND evidence_valid = 1
                ORDER BY ended_at DESC, gate_id DESC LIMIT 1""",
                (name, input_sha256, authority_sha256),
            ).fetchone()
            return None if row is None else dict(row)

    def invalidate_activation_evidence(
        self,
        *,
        experiment_id: str,
        from_order: int,
        input_sha256: str,
        authority_sha256: str,
        reason: str,
        invalidated_at: str,
        current_run_id: str,
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET evidence_valid = 0, invalidated_at = ?, invalidation_reason = ?
                WHERE run_id IN (
                    SELECT gate.run_id
                    FROM activation_gates AS gate
                    JOIN experiments AS parent ON parent.run_id = gate.run_id
                    WHERE parent.experiment_id = ? AND gate.run_id != ?
                      AND gate.gate_order = ?
                      AND (gate.input_sha256 != ? OR gate.authority_sha256 != ?)
                ) AND gate_order >= ? AND status = 'completed' AND evidence_valid = 1""",
                (
                    invalidated_at,
                    reason,
                    experiment_id,
                    current_run_id,
                    from_order,
                    input_sha256,
                    authority_sha256,
                    from_order,
                ),
            )
            return cursor.rowcount

    def get_activation_gates(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM activation_gates WHERE run_id = ? ORDER BY gate_order", (run_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if item["evidence_json"] is not None:
                item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    def reconcile_stale_activations(self, *, now: str) -> list[str]:
        reason = "activation interrupted before terminal persistence"
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT run_id, status FROM experiments
                WHERE mode = 'local_activation'
                  AND status NOT IN ('completed', 'failed')
                  AND lease_expires_at IS NOT NULL AND lease_expires_at < ?""",
                (now,),
            ).fetchall()
            run_ids = [row["run_id"] for row in rows]
            for row in rows:
                run_id = row["run_id"]
                connection.execute(
                    """UPDATE activation_gates SET status = 'failed', failure_reason = ?,
                        ended_at = ?, heartbeat_at = ?
                    WHERE run_id = ? AND status IN ('created', 'running')""",
                    (reason, now, now, run_id),
                )
                connection.execute(
                    """UPDATE experiments SET status = 'failed', failure_reason = ?, ended_at = ?,
                        heartbeat_at = ? WHERE run_id = ?""",
                    (reason, now, now, run_id),
                )
                connection.execute(
                    """INSERT INTO state_transitions(run_id, from_state, to_state, reason)
                    VALUES (?, ?, 'failed', ?)""",
                    (run_id, row["status"], reason),
                )
            return run_ids

    def create_attempt(
        self,
        *,
        attempt_id: str,
        config_path: str,
        raw_config_sha256: str | None,
        started_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO attempts(
                    attempt_id, config_path, raw_config_sha256, status, started_at
                ) VALUES (?, ?, ?, 'received', ?)""",
                (attempt_id, config_path, raw_config_sha256, started_at),
            )

    def link_attempt(self, attempt_id: str, run_id: str, ended_at: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (run_id, ended_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"attempt cannot be linked: {attempt_id}")

    def fail_attempt(self, attempt_id: str, reason: str, ended_at: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE attempts SET status = 'failed', failure_reason = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (reason, ended_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"attempt cannot be failed: {attempt_id}")

    def get_attempt(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown attempt: {attempt_id}")
            return dict(row)

    def transition(
        self, run_id: str, to_state: str, *, reason: str | None = None, ended_at: str | None = None
    ) -> None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT status FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown run: {run_id}")
            from_state = row["status"]
            if to_state not in TRANSITIONS[from_state]:
                raise DatabaseError(f"invalid transition: {from_state} -> {to_state}")
            if to_state in TERMINAL_STATES and ended_at is None:
                raise DatabaseError("terminal transition requires ended_at")
            if to_state == "failed" and not reason:
                raise DatabaseError("failed transition requires a reason")
            connection.execute(
                """UPDATE experiments
                SET status = ?, failure_reason = ?, ended_at = ?
                WHERE run_id = ?""",
                (to_state, reason if to_state == "failed" else None, ended_at, run_id),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state, reason)
                VALUES (?, ?, ?, ?)""",
                (run_id, from_state, to_state, reason),
            )

    def add_metric(self, run_id: str, name: str, value: Any, unit: str | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO metrics(run_id, name, value_json, unit) VALUES (?, ?, ?, ?)",
                (run_id, name, json.dumps(value, sort_keys=True, separators=(",", ":")), unit),
            )

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown run: {run_id}")
            result = dict(row)
            for key in ("config_json", "source_hashes_json", "runtime_json", "hardware_json"):
                result[key.removesuffix("_json")] = json.loads(result.pop(key))
            result["metrics"] = {
                item["name"]: {"value": json.loads(item["value_json"]), "unit": item["unit"]}
                for item in connection.execute("SELECT * FROM metrics WHERE run_id = ?", (run_id,))
            }
            result["transitions"] = [
                dict(item)
                for item in connection.execute(
                    """SELECT from_state, to_state, reason, occurred_at
                    FROM state_transitions WHERE run_id = ? ORDER BY id""",
                    (run_id,),
                )
            ]
            return result

    def spend_totals(self, phase: int) -> tuple[str, str]:
        total = Decimal("0")
        phase_total = Decimal("0")
        with self.connect() as connection:
            for row in connection.execute(
                "SELECT phase, modal_cost_actual_usd FROM experiments"
            ):
                cost = Decimal(row["modal_cost_actual_usd"])
                total += cost
                if row["phase"] == phase:
                    phase_total += cost
        return format(phase_total, "f"), format(total, "f")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "show"])
    parser.add_argument("--db", type=Path, default=Path("results/results.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id")
    args = parser.parse_args()
    database = ResultsDatabase(confine_results_db(args.root, args.db))
    database.initialize()
    if args.command == "show":
        if not args.run_id:
            parser.error("show requires --run-id")
        emit({"ok": True, "run": database.get_run(args.run_id)})
    else:
        emit({"ok": True, "database": str(args.db), "schema_version": SCHEMA_VERSION})


if __name__ == "__main__":
    main()
