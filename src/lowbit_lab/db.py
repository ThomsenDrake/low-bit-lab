from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any

from lowbit_lab.jsonio import emit

SCHEMA_VERSION = 1
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
    mode TEXT NOT NULL CHECK(mode IN ('local_dry_run', 'modal_dry_run')),
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
"""


class DatabaseError(RuntimeError):
    pass


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
            connection.executescript(SCHEMA)
            existing = connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            if existing is None:
                connection.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
            elif existing != SCHEMA_VERSION:
                raise DatabaseError(f"database schema {existing} != supported {SCHEMA_VERSION}")

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
    ) -> None:
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
                    modal_cost_requested_usd, modal_cost_actual_usd, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, '0', ?)""",
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
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state)
                VALUES (?, NULL, 'created')""",
                (run_id,),
            )

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
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT phase, modal_cost_actual_usd FROM experiments"
            ).fetchall()
        total = sum((Decimal(row["modal_cost_actual_usd"]) for row in rows), Decimal("0"))
        phase_total = sum(
            (Decimal(row["modal_cost_actual_usd"]) for row in rows if row["phase"] == phase),
            Decimal("0"),
        )
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
