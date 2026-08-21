from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from lowbit_lab.audit import begin_attempt, failure_reason
from lowbit_lab.budget import BudgetGuard
from lowbit_lab.config import (
    ConfigError,
    confine_experiment_config,
    load_experiment_config,
    verify_sources,
)
from lowbit_lab.db import ResultsDatabase, confine_results_db
from lowbit_lab.jsonio import emit
from lowbit_lab.runtime import hardware_metadata, runtime_metadata


def _now() -> str:
    return datetime.now(UTC).isoformat()


def run_local_dry_run(config_path: Path, db_path: Path, root: Path) -> dict[str, object]:
    root = root.resolve()
    db_path = confine_results_db(root, db_path)
    database = ResultsDatabase(db_path)
    database.initialize()
    config_path = confine_experiment_config(root, config_path)
    attempt_id = begin_attempt(database, config_path, root, _now())
    run_id: str | None = None
    try:
        config = load_experiment_config(config_path)
        if config.mode != "local_dry_run":
            raise ConfigError("local runner requires mode: local_dry_run")
        source_hashes = verify_sources(config, root)
        budget = BudgetGuard(root / "configs" / "budget-policy.json")
        authorization = budget.authorize(
            phase=config.phase, requested_cost_usd=config.modal.requested_cost_usd
        )
        run_id = str(uuid.uuid4())
        database.create_run(
            run_id=run_id,
            experiment_id=config.experiment_id,
            config_sha256=config.sha256,
            config_json=config.canonical_json,
            source_hashes=source_hashes,
            runtime=runtime_metadata(root, config.runtime_name, config.runtime_revision),
            hardware=hardware_metadata(),
            phase=config.phase,
            mode=config.mode,
            requested_cost=str(authorization.requested),
            started_at=_now(),
        )
        database.link_attempt(attempt_id, run_id, _now())
        database.transition(run_id, "validated")
        database.transition(run_id, "running")
        database.add_metric(run_id, "weights_loaded", False)
        database.add_metric(run_id, "modal_submitted", False)
        database.add_metric(
            run_id, "configured_context_tokens", config.configured_context_tokens, "tokens"
        )
        database.add_metric(run_id, "useful_context_proven", config.useful_context_proven)
        database.transition(run_id, "completed", ended_at=_now())
    except Exception as exc:
        attempt = database.get_attempt(attempt_id)
        if attempt["status"] == "received":
            database.fail_attempt(attempt_id, failure_reason(exc), _now())
        elif run_id is not None:
            database.transition(run_id, "failed", reason=failure_reason(exc), ended_at=_now())
        raise
    return {"ok": True, "attempt_id": attempt_id, "run": database.get_run(run_id)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path("results/results.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        emit(run_local_dry_run(args.config, args.db, args.root.resolve()))
    except Exception as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
