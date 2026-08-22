from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE
from lowbit_lab.jsonio import emit
from lowbit_lab.reference_contract import REFERENCE_RESOURCES

SCHEMA_VERSION = 4
REFERENCE_RESERVATION_USD = Decimal("4.00")
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
    mode TEXT NOT NULL CHECK(
        mode IN ('local_dry_run', 'modal_dry_run', 'local_activation', 'modal_reference')
    ),
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
CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES experiments(run_id) ON DELETE RESTRICT,
    experiment_id TEXT NOT NULL,
    phase INTEGER NOT NULL CHECK(phase = 1),
    status TEXT NOT NULL CHECK(status IN (
        'reserved', 'submitted', 'settlement_pending', 'settled',
        'released', 'failed', 'audit_blocked'
    )),
    requested_cost_usd TEXT NOT NULL,
    provider_actual_cost_usd TEXT,
    provider_job_id TEXT UNIQUE,
    app_identity TEXT,
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
    CHECK((status IN ('submitted', 'settlement_pending', 'settled', 'audit_blocked')
           AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
          OR status NOT IN ('submitted', 'settlement_pending', 'settled', 'audit_blocked'))
);
CREATE UNIQUE INDEX IF NOT EXISTS budget_reservations_active_experiment
ON budget_reservations(experiment_id)
WHERE status IN ('reserved', 'submitted', 'settlement_pending', 'audit_blocked');
CREATE TABLE IF NOT EXISTS reference_approval_challenges (
    challenge_sha256 TEXT PRIMARY KEY CHECK(length(challenge_sha256) = 64),
    packet_sha256 TEXT NOT NULL CHECK(length(packet_sha256) = 64),
    approval_digest TEXT UNIQUE CHECK(approval_digest IS NULL OR length(approval_digest) = 64),
    expires_at TEXT,
    consumed_at TEXT,
    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    CHECK((approval_digest IS NULL AND expires_at IS NULL AND consumed_at IS NULL)
          OR (approval_digest IS NOT NULL AND expires_at IS NOT NULL)),
    CHECK(consumed_at IS NULL OR run_id IS NOT NULL)
);
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


def _database_money(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError) as exc:
        raise DatabaseError(f"{label} must be a decimal string") from exc
    if (
        not isinstance(value, str)
        or not parsed.is_finite()
        or parsed < 0
        or parsed.as_tuple().exponent < -6
    ):
        raise DatabaseError(f"{label} must be finite, non-negative, and at most 6 decimals")
    return parsed


def _database_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DatabaseError(f"{label} must be lowercase SHA-256")
    return value


def _database_timestamp(value: str, label: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise DatabaseError(f"{label} must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise DatabaseError(f"{label} must be timezone-aware")
    return timestamp


def _reference_challenge(config_json: str, config_sha256: str) -> tuple[str, dict[str, Any]]:
    try:
        raw = json.loads(config_json)
    except json.JSONDecodeError as exc:
        raise DatabaseError("reference config must be canonical JSON") from exc
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if canonical != config_json or hashlib.sha256(canonical.encode()).hexdigest() != config_sha256:
        raise DatabaseError("reference config identity mismatch")
    top_fields = {
        "schema_version",
        "kind",
        "experiment_id",
        "approved_plan_path",
        "approved_plan_sha256",
        "budget_policy_path",
        "inputs",
        "authority_files",
        "resources",
        "provider",
        "gates",
        "approval_artifact_path",
    }
    input_fields = {
        "weight_inventory_sha256",
        "weight_inventory_tensor_bytes",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "evaluation_lock_sha256",
        "evaluation_max_context_tokens",
        "formula_authority_sha256",
        "reviewed_commit_sha256",
        "control_plane_sha256",
    }
    authority_fields = {
        "weight_inventory_path",
        "source_shard_metadata_path",
        "provenance_manifest_path",
        "runtime_lock_path",
        "runtime_receipt_path",
        "evaluation_lock_path",
        "evaluation_fixture_root",
    }
    provider_fields = {
        "submit",
        "scheduling_enabled",
        "cloud_upload",
        "mounts",
        "volumes",
        "secrets",
        "credentials_source",
        "safety_evidence_path",
        "safety_evidence_sha256",
    }
    gate_fields = {
        "memory_fit_evidence_path",
        "memory_fit_evidence_sha256",
        "cold_path_time_evidence_path",
        "cold_path_time_evidence_sha256",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != top_fields
        or raw.get("schema_version") != 1
        or raw.get("kind") != "modal_reference_preview"
        or not isinstance(raw.get("inputs"), dict)
        or set(raw["inputs"]) != input_fields
        or raw.get("resources") != REFERENCE_RESOURCES
        or not isinstance(raw.get("authority_files"), dict)
        or set(raw["authority_files"]) != authority_fields
        or not isinstance(raw.get("provider"), dict)
        or set(raw["provider"]) != provider_fields
        or not isinstance(raw.get("gates"), dict)
        or set(raw["gates"]) != gate_fields
    ):
        raise DatabaseError("reference config schema is invalid")
    provider = raw["provider"]
    if (
        provider["submit"] is not False
        or provider["scheduling_enabled"] is not False
        or provider["cloud_upload"] is not False
        or provider["mounts"] != []
        or provider["volumes"] != []
        or provider["secrets"] != []
        or provider["credentials_source"] != "provider_local"
    ):
        raise DatabaseError("reference provider boundary is invalid")
    if (
        not str(raw["approved_plan_path"]).startswith("docs/plans/local/")
        or SHA256_RE.fullmatch(str(raw["approved_plan_sha256"])) is None
        or not str(raw["budget_policy_path"]).startswith("configs/local/")
        or (
            raw["approval_artifact_path"] is not None
            and not str(raw["approval_artifact_path"]).startswith("configs/local/")
        )
    ):
        raise DatabaseError("reference authority paths or hashes are invalid")
    challenge_material = {
        key: value for key, value in raw.items() if key != "approval_artifact_path"
    }
    challenge_json = json.dumps(
        challenge_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(challenge_json.encode()).hexdigest(), raw


def _database_private_data_scan(value: object, *, path: str = "reference") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if key not in {"credentials_source", "secrets"} and any(
                marker in lowered
                for marker in ("password", "passwd", "credential", "secret", "api_key")
            ):
                raise DatabaseError(f"private or credential-shaped field is forbidden: {path}")
            _database_private_data_scan(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _database_private_data_scan(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and (
        re.search(r"(?i)(?:^|\s)[A-Z]:[\\/]", value)
        or re.search(r"(?i)/(?:mnt/[a-z]/Users|home)/[^/\s]+/", value)
        or re.search(r"\bAKIA[0-9A-Z]{16}\b", value)
        or re.search(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b", value)
        or re.search(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}", value)
        or re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", value)
    ):
        raise DatabaseError(f"private machine path is forbidden: {path}")


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
        or IMMUTABLE_REVISION_RE.fullmatch(target["revision"]) is None
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
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
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
                existing = 3
            if existing == 3:
                self._migrate_v3_to_v4(connection)
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
                (3,),
            )
        except Exception as exc:
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v3 migration failed: {exc}") from exc

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = connection.execute("SELECT count(*) FROM experiments").fetchone()[0]
            connection.execute(
                """CREATE TABLE experiments_v4 (
                    run_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL
                        REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
                    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
                    config_json TEXT NOT NULL,
                    source_hashes_json TEXT NOT NULL,
                    runtime_json TEXT NOT NULL,
                    hardware_json TEXT NOT NULL,
                    phase INTEGER NOT NULL CHECK(phase >= 0),
                    mode TEXT NOT NULL CHECK(mode IN (
                        'local_dry_run', 'modal_dry_run', 'local_activation', 'modal_reference'
                    )),
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
                )"""
            )
            columns = (
                "run_id, experiment_id, config_sha256, config_json, source_hashes_json, "
                "runtime_json, hardware_json, phase, mode, status, modal_cost_requested_usd, "
                "modal_cost_actual_usd, failure_reason, owner_id, lease_expires_at, heartbeat_at, "
                "started_at, ended_at"
            )
            connection.execute(
                f"INSERT INTO experiments_v4 ({columns}) SELECT {columns} FROM experiments"
            )
            if connection.execute("SELECT count(*) FROM experiments_v4").fetchone()[0] != before:
                raise DatabaseError("schema v4 experiment row-count validation failed")
            connection.execute("DROP INDEX IF EXISTS experiments_config_sha")
            connection.execute("DROP TABLE experiments")
            connection.execute("ALTER TABLE experiments_v4 RENAME TO experiments")
            connection.execute("CREATE INDEX experiments_config_sha ON experiments(config_sha256)")
            migration_script = (
                """CREATE TABLE budget_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL UNIQUE REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    experiment_id TEXT NOT NULL,
                    phase INTEGER NOT NULL CHECK(phase = 1),
                    status TEXT NOT NULL CHECK(status IN (
                        'reserved', 'submitted', 'settlement_pending', 'settled',
                        'released', 'failed', 'audit_blocked'
                    )),
                    requested_cost_usd TEXT NOT NULL,
                    provider_actual_cost_usd TEXT,
                    provider_job_id TEXT UNIQUE,
                    app_identity TEXT,
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
                    CHECK((status IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                           ) AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                          OR status NOT IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                          ))
                );
                CREATE UNIQUE INDEX budget_reservations_active_experiment
                ON budget_reservations(experiment_id)
                WHERE status IN ('reserved', 'submitted', 'settlement_pending', 'audit_blocked');
                CREATE TABLE reference_approval_challenges (
                    challenge_sha256 TEXT PRIMARY KEY CHECK(length(challenge_sha256) = 64),
                    packet_sha256 TEXT NOT NULL CHECK(length(packet_sha256) = 64),
                    approval_digest TEXT UNIQUE
                        CHECK(approval_digest IS NULL OR length(approval_digest) = 64),
                    expires_at TEXT,
                    consumed_at TEXT,
                    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    created_at TEXT NOT NULL,
                    CHECK((approval_digest IS NULL AND expires_at IS NULL AND consumed_at IS NULL)
                          OR (approval_digest IS NOT NULL AND expires_at IS NOT NULL)),
                    CHECK(consumed_at IS NULL OR run_id IS NOT NULL)
                );"""
            )
            for statement in migration_script.split(";"):
                if statement.strip():
                    connection.execute(statement)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v4 foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v4 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

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

    def reserve_reference_run(
        self,
        *,
        reservation_id: str,
        attempt_id: str,
        run_id: str,
        experiment_id: str,
        config_sha256: str,
        config_json: str,
        source_hashes: dict[str, str],
        runtime: dict[str, Any],
        hardware: dict[str, Any],
        requested_cost_usd: str,
        phase_cap_usd: str,
        total_cap_usd: str,
        single_job_cap_usd: str,
        idempotency_key: str,
        owner_id: str,
        lease_expires_at: str,
        started_at: str,
        challenge_sha256: str,
        approval_digest: str,
    ) -> None:
        requested = _database_money(requested_cost_usd, "requested_cost_usd")
        phase_cap = _database_money(phase_cap_usd, "phase_cap_usd")
        total_cap = _database_money(total_cap_usd, "total_cap_usd")
        single_job_cap = _database_money(single_job_cap_usd, "single_job_cap_usd")
        if (
            requested != REFERENCE_RESERVATION_USD
            or single_job_cap != REFERENCE_RESERVATION_USD
            or phase_cap != REFERENCE_RESERVATION_USD
            or total_cap != REFERENCE_RESERVATION_USD
        ):
            raise DatabaseError("reference reservation and all caps must equal USD 4.00")
        if not owner_id or not idempotency_key:
            raise DatabaseError("reference reservation requires owner and idempotency key")
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(approval_digest, "approval_digest")
        expected_challenge, parsed_config = _reference_challenge(config_json, config_sha256)
        if expected_challenge != challenge_sha256:
            raise DatabaseError("reference approval is not bound to the canonical config")
        inputs = parsed_config.get("inputs")
        if not isinstance(inputs, dict):
            raise DatabaseError("reference config inputs are incomplete")
        expected_sources = {
            name: value
            for name, value in inputs.items()
            if name not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
            and value is not None
        }
        if source_hashes != expected_sources:
            raise DatabaseError("reference source lineage does not match the canonical config")
        if runtime != {"receipt_sha256": inputs.get("runtime_receipt_sha256")}:
            raise DatabaseError("reference runtime lineage does not match the canonical config")
        for label, value in (
            ("config", parsed_config),
            ("source_hashes", source_hashes),
            ("runtime", runtime),
            ("hardware", hardware),
        ):
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode()) > 1_000_000:
                raise DatabaseError(f"reference {label} exceeds the audit record limit")
            _database_private_data_scan(value, path=label)
        start_time = _database_timestamp(started_at, "started_at")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            approval = connection.execute(
                """SELECT approval_digest, expires_at, consumed_at
                FROM reference_approval_challenges WHERE challenge_sha256 = ?""",
                (challenge_sha256,),
            ).fetchone()
            if (
                approval is None
                or approval["approval_digest"] != approval_digest
                or approval["consumed_at"] is not None
                or approval["expires_at"] is None
                or _database_timestamp(approval["expires_at"], "expires_at") <= start_time
            ):
                raise DatabaseError(
                    "reference approval is missing, expired, mismatched, or consumed"
                )
            committed = Decimal("0")
            for row in connection.execute(
                """SELECT status, requested_cost_usd, provider_actual_cost_usd
                FROM budget_reservations
                WHERE status NOT IN ('released', 'failed')"""
            ):
                value = (
                    row["provider_actual_cost_usd"]
                    if row["status"] == "settled"
                    else row["requested_cost_usd"]
                )
                committed += _database_money(value, "stored reservation cost")
            if committed + requested > phase_cap or committed + requested > total_cap:
                raise DatabaseError("reference reservation exceeds phase or total cap")
            registered = connection.execute(
                "SELECT config_sha256, config_json FROM experiment_configs WHERE experiment_id = ?",
                (experiment_id,),
            ).fetchone()
            if registered is None:
                cursor = connection.execute(
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
            attempt = connection.execute(
                "SELECT status FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None or attempt["status"] != "received":
                raise DatabaseError(f"attempt cannot be linked: {attempt_id}")
            connection.execute(
                """INSERT INTO experiments(
                    run_id, experiment_id, config_sha256, config_json, source_hashes_json,
                    runtime_json, hardware_json, phase, mode, status,
                    modal_cost_requested_usd, modal_cost_actual_usd, owner_id,
                    lease_expires_at, heartbeat_at, started_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 1, 'modal_reference', 'created', ?, '0', ?, ?, ?, ?
                )""",
                (
                    run_id,
                    experiment_id,
                    config_sha256,
                    config_json,
                    json.dumps(source_hashes, sort_keys=True, separators=(",", ":")),
                    json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                    json.dumps(hardware, sort_keys=True, separators=(",", ":")),
                    requested_cost_usd,
                    owner_id,
                    lease_expires_at,
                    started_at,
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state)
                VALUES (?, NULL, 'created')""",
                (run_id,),
            )
            connection.execute(
                """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (run_id, started_at, attempt_id),
            )
            connection.execute(
                """INSERT INTO budget_reservations(
                    reservation_id, run_id, experiment_id, phase, status, requested_cost_usd,
                    idempotency_key, owner_id, lease_expires_at, heartbeat_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 1, 'reserved', ?, ?, ?, ?, ?, ?, ?)""",
                (
                    reservation_id,
                    run_id,
                    experiment_id,
                    requested_cost_usd,
                    idempotency_key,
                    owner_id,
                    lease_expires_at,
                    started_at,
                    started_at,
                    started_at,
                ),
            )
            cursor = connection.execute(
                """UPDATE reference_approval_challenges SET consumed_at = ?, run_id = ?
                WHERE challenge_sha256 = ? AND approval_digest = ? AND consumed_at IS NULL""",
                (started_at, run_id, challenge_sha256, approval_digest),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference approval could not be consumed atomically")

    def register_reference_challenge(
        self, *, challenge_sha256: str, packet_sha256: str, created_at: str
    ) -> None:
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(packet_sha256, "packet_sha256")
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO reference_approval_challenges(
                    challenge_sha256, packet_sha256, created_at
                ) VALUES (?, ?, ?)""",
                (challenge_sha256, packet_sha256, created_at),
            )

    def attach_reference_approval(
        self, *, challenge_sha256: str, approval_digest: str, expires_at: str
    ) -> None:
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(approval_digest, "approval_digest")
        _database_timestamp(expires_at, "expires_at")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE reference_approval_challenges
                SET approval_digest = ?, expires_at = ?
                WHERE challenge_sha256 = ? AND approval_digest IS NULL AND consumed_at IS NULL""",
                (approval_digest, expires_at, challenge_sha256),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference approval cannot be attached")

    def mark_reservation_submitted(
        self,
        reservation_id: str,
        *,
        provider_job_id: str,
        app_identity: str,
        occurred_at: str,
    ) -> None:
        if not provider_job_id or not app_identity:
            raise DatabaseError("submitted reservation requires provider identity")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'submitted', provider_job_id = ?, app_identity = ?,
                    heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'reserved'""",
                (provider_job_id, app_identity, occurred_at, occurred_at, reservation_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"reservation cannot be submitted: {reservation_id}")

    def mark_settlement_pending(self, reservation_id: str, *, occurred_at: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'settlement_pending', heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'submitted'""",
                (occurred_at, occurred_at, reservation_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"reservation cannot await settlement: {reservation_id}")

    def settle_reservation(
        self,
        reservation_id: str,
        *,
        actual_cost_usd: str,
        settlement_identity: str,
        occurred_at: str,
    ) -> None:
        actual = _database_money(actual_cost_usd, "actual_cost_usd")
        if not settlement_identity:
            raise DatabaseError("settlement requires provider attribution")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT run_id, requested_cost_usd, status FROM budget_reservations
                WHERE reservation_id = ?""",
                (reservation_id,),
            ).fetchone()
            if row is None or row["status"] not in {"submitted", "settlement_pending"}:
                raise DatabaseError(f"reservation cannot settle: {reservation_id}")
            if actual > _database_money(row["requested_cost_usd"], "requested_cost_usd"):
                raise DatabaseError("provider actual cost exceeds reserved cap")
            cursor = connection.execute(
                """UPDATE budget_reservations SET status = 'settled',
                    provider_actual_cost_usd = ?, settlement_identity = ?, heartbeat_at = ?,
                    updated_at = ? WHERE reservation_id = ?
                    AND status IN ('submitted', 'settlement_pending')""",
                (actual_cost_usd, settlement_identity, occurred_at, occurred_at, reservation_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"reservation cannot settle: {reservation_id}")
            connection.execute(
                "UPDATE experiments SET modal_cost_actual_usd = ? WHERE run_id = ?",
                (actual_cost_usd, row["run_id"]),
            )

    def get_reservation(self, reservation_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown reservation: {reservation_id}")
            return dict(row)

    def reconcile_stale_reservations(self, *, now: str) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {"released": [], "audit_blocked": []}
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT reservation_id, status FROM budget_reservations
                WHERE status IN ('reserved', 'submitted', 'settlement_pending')
                  AND lease_expires_at < ? ORDER BY reservation_id""",
                (now,),
            ).fetchall()
            for row in rows:
                next_state = "released" if row["status"] == "reserved" else "audit_blocked"
                reason = (
                    "stale reservation released before submission"
                    if next_state == "released"
                    else "provider state or billing attribution requires manual audit"
                )
                cursor = connection.execute(
                    """UPDATE budget_reservations SET status = ?, failure_reason = ?,
                        heartbeat_at = ?, updated_at = ? WHERE reservation_id = ? AND status = ?""",
                    (next_state, reason, now, now, row["reservation_id"], row["status"]),
                )
                if cursor.rowcount == 1:
                    result[next_state].append(row["reservation_id"])
                    run = connection.execute(
                        "SELECT run_id, status FROM experiments WHERE run_id = ("
                        "SELECT run_id FROM budget_reservations WHERE reservation_id = ?)",
                        (row["reservation_id"],),
                    ).fetchone()
                    if run is not None and run["status"] not in TERMINAL_STATES:
                        if next_state == "released":
                            connection.execute(
                                """UPDATE experiments SET status = 'failed', failure_reason = ?,
                                    ended_at = ? WHERE run_id = ?""",
                                (reason, now, run["run_id"]),
                            )
                            connection.execute(
                                """INSERT INTO state_transitions(
                                    run_id, from_state, to_state, reason, occurred_at
                                ) VALUES (?, ?, 'failed', ?, ?)""",
                                (run["run_id"], run["status"], reason, now),
                            )
                        else:
                            connection.execute(
                                "UPDATE experiments SET failure_reason = ? WHERE run_id = ?",
                                (reason, run["run_id"]),
                            )
        return result

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
