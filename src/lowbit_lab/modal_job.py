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


def plan_modal_dry_run(
    config_path: Path, db_path: Path, root: Path, *, dry_run: bool
) -> dict[str, object]:
    if not dry_run:
        raise ConfigError("Modal submission is not implemented or authorized; pass --dry-run")
    root = root.resolve()
    db_path = confine_results_db(root, db_path)
    database = ResultsDatabase(db_path)
    database.initialize()
    config_path = confine_experiment_config(root, config_path)
    attempt_id = begin_attempt(database, config_path, root, _now())
    run_id: str | None = None
    try:
        config = load_experiment_config(config_path)
        if config.mode != "modal_dry_run":
            raise ConfigError("Modal wrapper requires mode: modal_dry_run")
        source_hashes = verify_sources(config, root)
        guard = BudgetGuard(root / "configs" / "budget-policy.json")
        phase_spent, total_spent = database.spend_totals(config.phase)
        authorization = guard.authorize(
            phase=config.phase,
            requested_cost_usd=config.modal.requested_cost_usd,
            phase_spent_usd=phase_spent,
            total_spent_usd=total_spent,
        )
        derived_max_cost = guard.estimate_h100_cost(
            config.modal.gpu_count, config.modal.wall_clock_seconds
        )
        if derived_max_cost > authorization.requested:
            raise ConfigError("resource-derived maximum cost exceeds the requested budget cap")
        job_plan = {
            "submit": False,
            "dry_run": True,
            "phase": config.phase,
            "budget_cap_usd": str(authorization.requested),
            "resource_derived_max_cost_usd": str(derived_max_cost),
            "gpu_type": config.modal.gpu_type,
            "gpu_count": config.modal.gpu_count,
            "wall_clock_seconds": config.modal.wall_clock_seconds,
            "checkpoint_path": config.modal.checkpoint_path,
            "cleanup": config.modal.cleanup,
            "cloud_upload": False,
            "weights_required": False,
            "stop_conditions": [
                "budget_cap_reached",
                "wall_clock_reached",
                "checkpoint_failure",
                "unknown_failure_mode",
            ],
        }
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
        database.add_metric(run_id, "modal_job_plan", job_plan)
        database.add_metric(run_id, "modal_submitted", False)
        database.transition(run_id, "completed", ended_at=_now())
    except Exception as exc:
        attempt = database.get_attempt(attempt_id)
        if attempt["status"] == "received":
            database.fail_attempt(attempt_id, failure_reason(exc), _now())
        elif run_id is not None:
            database.transition(run_id, "failed", reason=failure_reason(exc), ended_at=_now())
        raise
    return {
        "ok": True,
        "attempt_id": attempt_id,
        "job_plan": job_plan,
        "run": database.get_run(run_id),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path("results/results.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        emit(plan_modal_dry_run(args.config, args.db, args.root.resolve(), dry_run=args.dry_run))
    except Exception as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
