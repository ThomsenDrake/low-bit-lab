from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lowbit_lab.budget import ReferenceBudgetGuard
from lowbit_lab.config import confine_experiment_config
from lowbit_lab.db import DatabaseError, ResultsDatabase, confine_results_db
from lowbit_lab.handoff import (
    build_pre_spend_handoff,
    canonical_json,
    sha256_json,
    validate_pre_spend_handoff,
)
from lowbit_lab.jsonio import emit
from lowbit_lab.modal_job import (
    ReferenceJobConfig,
    load_reference_job_config,
    plan_reference_preview,
)

STANDING_STATEMENT_SHA256 = (
    "7a7648f1844dcd532bf9c34d2a47cbcd031c86efb9e6f3338c008ad873339323"
)
FORMULA_APPROVAL_STATEMENT_SHA256 = (
    "87b42e40c2a290e01d87b721bf381c3c5e259d1eb0a4660e41fdbf8bc73f7ddd"
)
REVIEWED_FORMULA_SHA256 = (
    "b7d1b7495f2f5396059c693dcde62525a278854b4b8953ce300cd6054f31c163"
)
APPROVED_FORMULA_SHA256 = (
    "a2ee227c0cba04ac2b9af3ff1ca293fe0aabe4b2abe71f7f949a8d54f1f93e68"
)
CONTROLLER_PLAN_PATH = (
    "docs/plans/2026-08-23-1518-feat-zero-spend-readiness-controller-plan.md"
)
ALLOWED_ACTIONS = ("prepare", "status", "verify")
FORBIDDEN_ACTIONS = (
    "approval_creation",
    "credentials",
    "destructive_cleanup",
    "modal_remote_execution",
    "nonzero_budget_reservation",
    "provider_submission",
    "retries",
    "scheduling",
    "secrets",
    "u8",
    "volumes_or_mounts",
    "weight_transfer",
)
MAX_CONTROL_ARTIFACT_BYTES = 1024 * 1024


class ControllerError(ValueError):
    pass


@dataclass(frozen=True)
class ControllerInputs:
    config: ReferenceJobConfig
    standing_authority_sha256: str
    formula_approval_sha256: str
    context_sha256: str
    handoff: dict[str, Any]


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_CONTROL_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise ControllerError(f"cannot read local input: {path.name}") from exc
    if len(content) > MAX_CONTROL_ARTIFACT_BYTES:
        raise ControllerError(f"local input exceeds byte limit: {path.name}")
    return content


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(_read_bounded(path)).hexdigest()


def _local_path(root: Path, value: Path, prefix: str) -> Path:
    root = root.resolve()
    candidate = (root / value).resolve() if not value.is_absolute() else value.resolve()
    if not candidate.is_relative_to((root / prefix).resolve()):
        raise ControllerError(f"local input must stay under {prefix}")
    return candidate


def _load_closed_json(path: Path, fields: set[str], label: str) -> tuple[dict[str, Any], str]:
    try:
        content = _read_bounded(path)
        raw = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot read {label}") from exc
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ControllerError(f"{label} schema is closed")
    return raw, hashlib.sha256(content).hexdigest()


def validate_standing_authority(root: Path, path: Path) -> tuple[str, str]:
    path = _local_path(root, path, "configs/local")
    raw, digest = _load_closed_json(
        path,
        {
            "schema_version",
            "kind",
            "statement_sha256",
            "controlling_plan_path",
            "controlling_plan_sha256",
            "allowed_actions",
            "forbidden_actions",
            "scope",
            "expires_at",
            "human_origin",
        },
        "standing authority receipt",
    )
    if raw["schema_version"] != 1 or raw["kind"] != "zero_spend_standing_authority":
        raise ControllerError("unsupported standing authority receipt")
    if raw["statement_sha256"] != STANDING_STATEMENT_SHA256:
        raise ControllerError("standing authority statement mismatch")
    if raw["controlling_plan_path"] != CONTROLLER_PLAN_PATH:
        raise ControllerError("standing authority plan path mismatch")
    plan_path = root.resolve() / CONTROLLER_PLAN_PATH
    plan_sha256 = _file_sha256(plan_path)
    if raw["controlling_plan_sha256"] != plan_sha256:
        raise ControllerError("standing authority plan digest mismatch")
    if raw["allowed_actions"] != list(ALLOWED_ACTIONS):
        raise ControllerError("standing authority action set changed")
    if raw["forbidden_actions"] != list(FORBIDDEN_ACTIONS):
        raise ControllerError("standing authority forbidden set changed")
    if raw["scope"] != "zero_spend_preparation" or raw["human_origin"] != "attested":
        raise ControllerError("standing authority scope is invalid")
    if raw["expires_at"] is not None:
        try:
            expires_at = datetime.fromisoformat(raw["expires_at"])
        except (TypeError, ValueError) as exc:
            raise ControllerError("standing authority expiry is invalid") from exc
        if expires_at.tzinfo is None or datetime.now(UTC) >= expires_at:
            raise ControllerError("standing authority is expired")
    return digest, plan_sha256


def validate_formula_approval(root: Path, path: Path, config: ReferenceJobConfig) -> str:
    path = _local_path(root, path, "reports/local")
    raw, digest = _load_closed_json(
        path,
        {
            "schema_version",
            "kind",
            "statement_sha256",
            "reviewed_formula_sha256",
            "approved_formula_sha256",
            "formula_authority_path",
            "human_origin",
        },
        "formula approval receipt",
    )
    if raw["schema_version"] != 1 or raw["kind"] != "formula_approval_receipt":
        raise ControllerError("unsupported formula approval receipt")
    if (
        raw["statement_sha256"] != FORMULA_APPROVAL_STATEMENT_SHA256
        or raw["reviewed_formula_sha256"] != REVIEWED_FORMULA_SHA256
        or raw["approved_formula_sha256"] != APPROVED_FORMULA_SHA256
        or raw["human_origin"] != "attested"
    ):
        raise ControllerError("formula approval lineage mismatch")
    configured_path = config.gates.get("formula_authority_path")
    if raw["formula_authority_path"] != configured_path or configured_path is None:
        raise ControllerError("formula approval path mismatch")
    configured_receipt_path = config.gates.get("formula_approval_path")
    configured_receipt_sha = config.gates.get("formula_approval_sha256")
    if (
        configured_receipt_path is None
        or path != (root.resolve() / configured_receipt_path).resolve()
        or configured_receipt_sha != digest
    ):
        raise ControllerError("formula approval receipt is not config-bound")
    actual = _file_sha256(_local_path(root, Path(configured_path), "reports/local"))
    if actual != APPROVED_FORMULA_SHA256 or config.inputs["formula_authority_sha256"] != actual:
        raise ControllerError("approved formula artifact mismatch")
    return digest


def _context_sha256(
    *,
    config: ReferenceJobConfig,
    controller_plan_sha256: str,
    standing_authority_sha256: str,
    formula_approval_sha256: str,
) -> str:
    material = {
        "schema_version": 1,
        "controller_plan_sha256": controller_plan_sha256,
        "config_sha256": config.sha256,
        "challenge_sha256": config.challenge_sha256,
        "reviewed_commit_sha256": config.inputs["reviewed_commit_sha256"],
        "control_plane_sha256": config.inputs["control_plane_sha256"],
        "standing_authority_sha256": standing_authority_sha256,
        "formula_approval_sha256": formula_approval_sha256,
    }
    return sha256_json(material)


def prepare_inputs(
    *, root: Path, config_path: Path, authority_path: Path, formula_approval_path: Path
) -> ControllerInputs:
    root = root.resolve()
    config = load_reference_job_config(
        confine_experiment_config(root, config_path), root=root
    )
    standing_sha, controller_plan_sha = validate_standing_authority(root, authority_path)
    formula_approval_sha = validate_formula_approval(root, formula_approval_path, config)
    preview = plan_reference_preview(config, root=root)
    context_sha = _context_sha256(
        config=config,
        controller_plan_sha256=controller_plan_sha,
        standing_authority_sha256=standing_sha,
        formula_approval_sha256=formula_approval_sha,
    )
    handoff = build_pre_spend_handoff(
        preview=preview,
        reviewed_commit_sha256=str(config.inputs["reviewed_commit_sha256"]),
        control_plane_sha256=str(config.inputs["control_plane_sha256"]),
        standing_authority_sha256=standing_sha,
        formula_approval_sha256=formula_approval_sha,
        controller_context_sha256=context_sha,
        configured_context_tokens=int(config.inputs["evaluation_max_context_tokens"]),
        total_ledger_ceiling_usd=format(
            ReferenceBudgetGuard(
                root / config.budget_policy_path,
                expected_plan_sha256=config.original_approved_plan_sha256,
            ).total_cap,
            "f",
        ),
    )
    return ControllerInputs(
        config=config,
        standing_authority_sha256=standing_sha,
        formula_approval_sha256=formula_approval_sha,
        context_sha256=context_sha,
        handoff=handoff,
    )


def controller_status(
    *, root: Path, config_path: Path, authority_path: Path, formula_approval_path: Path
) -> dict[str, Any]:
    prepared = prepare_inputs(
        root=root,
        config_path=config_path,
        authority_path=authority_path,
        formula_approval_path=formula_approval_path,
    )
    return {
        "ok": True,
        "operation": "status",
        "mutated": False,
        "context_sha256": prepared.context_sha256,
        "blockers": prepared.handoff["blockers"],
        "paid_action_ready": False,
        "command_available": False,
        "actual_cost_usd": "0",
    }


def controller_prepare(
    *,
    root: Path,
    config_path: Path,
    db_path: Path,
    authority_path: Path,
    formula_approval_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    root = root.resolve()
    prepared = prepare_inputs(
        root=root,
        config_path=config_path,
        authority_path=authority_path,
        formula_approval_path=formula_approval_path,
    )
    confined_db_path = confine_results_db(root, db_path)
    database = ResultsDatabase(confined_db_path)
    database.initialize()
    cycle_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    workspace_id = hashlib.sha256(root.as_posix().encode()).hexdigest()
    generation = database.acquire_controller_cycle(
        cycle_id=cycle_id,
        workspace_id=workspace_id,
        owner_id=owner_id,
        context_sha256=prepared.context_sha256,
        authority_sha256=prepared.standing_authority_sha256,
        selected_action="prepare",
        started_at=now.isoformat(),
        lease_expires_at=(now + timedelta(minutes=5)).isoformat(),
    )
    database.transition_controller_cycle(
        cycle_id=cycle_id,
        owner_id=owner_id,
        generation=generation,
        context_sha256=prepared.context_sha256,
        authority_sha256=prepared.standing_authority_sha256,
        from_state="created",
        to_state="validated",
        occurred_at=datetime.now(UTC).isoformat(),
    )
    database.transition_controller_cycle(
        cycle_id=cycle_id,
        owner_id=owner_id,
        generation=generation,
        context_sha256=prepared.context_sha256,
        authority_sha256=prepared.standing_authority_sha256,
        from_state="validated",
        to_state="preparing",
        occurred_at=datetime.now(UTC).isoformat(),
    )
    payload = canonical_json(prepared.handoff).encode()
    try:
        output_root = _local_path(root, output_dir, "reports/local")
        output_root.mkdir(parents=True, exist_ok=True)
        artifact_path = output_root / f"pre-spend-handoff-{cycle_id}.json"
        with artifact_path.open("xb") as handle:
            handle.write(payload)
        persisted_payload = _read_bounded(artifact_path)
        if persisted_payload != payload:
            raise ControllerError("persisted handoff bytes changed")
    except (OSError, ControllerError) as exc:
        database.fail_controller_cycle(
            cycle_id=cycle_id,
            owner_id=owner_id,
            generation=generation,
            context_sha256=prepared.context_sha256,
            authority_sha256=prepared.standing_authority_sha256,
            from_state="preparing",
            occurred_at=datetime.now(UTC).isoformat(),
            stop_reason="artifact_persistence_failed",
        )
        if isinstance(exc, ControllerError):
            raise
        raise ControllerError("cannot write immutable handoff") from exc
    artifact_sha = hashlib.sha256(persisted_payload).hexdigest()
    relative_artifact = artifact_path.relative_to(root).as_posix()
    terminal_state = str(prepared.handoff["status"])
    database.finalize_controller_cycle(
        cycle_id=cycle_id,
        owner_id=owner_id,
        generation=generation,
        context_sha256=prepared.context_sha256,
        authority_sha256=prepared.standing_authority_sha256,
        from_state="preparing",
        to_state=terminal_state,
        occurred_at=datetime.now(UTC).isoformat(),
        stop_reason=(
            "paid_plan_and_empirical_evidence_required"
            if terminal_state == "paid_decision_required"
            else "locally_resolvable_gate_failed"
        ),
        artifact_path=relative_artifact,
        artifact_sha256=artifact_sha,
    )
    return {
        "ok": True,
        "operation": "prepare",
        "cycle_id": cycle_id,
        "generation": generation,
        "state": terminal_state,
        "context_sha256": prepared.context_sha256,
        "artifact_path": relative_artifact,
        "artifact_sha256": artifact_sha,
        "handoff": prepared.handoff,
    }


def controller_verify(
    *,
    root: Path,
    config_path: Path,
    db_path: Path,
    authority_path: Path,
    formula_approval_path: Path,
) -> dict[str, Any]:
    root = root.resolve()
    prepared = prepare_inputs(
        root=root,
        config_path=config_path,
        authority_path=authority_path,
        formula_approval_path=formula_approval_path,
    )
    confined_db_path = confine_results_db(root, db_path)
    if not confined_db_path.is_file():
        raise ControllerError("controller database does not exist")
    database = ResultsDatabase(confined_db_path)
    workspace_id = hashlib.sha256(root.as_posix().encode()).hexdigest()
    cycle = database.get_latest_controller_cycle_readonly(workspace_id)
    if cycle is None:
        raise ControllerError("no controller cycle exists")
    if cycle["state"] not in {"paid_decision_required", "stopped"}:
        raise ControllerError("latest controller cycle is not terminal")
    if cycle["context_sha256"] != prepared.context_sha256:
        raise ControllerError("controller context drift")
    artifact_path = _local_path(
        root, Path(str(cycle["artifact_path"])), "reports/local"
    )
    try:
        artifact_bytes = _read_bounded(artifact_path)
        raw = json.loads(artifact_bytes)
    except json.JSONDecodeError as exc:
        raise ControllerError("cannot read committed handoff") from exc
    validate_pre_spend_handoff(raw)
    expected = canonical_json(prepared.handoff).encode()
    actual = canonical_json(raw).encode()
    if (
        artifact_bytes != actual
        or hashlib.sha256(artifact_bytes).hexdigest() != cycle["artifact_sha256"]
        or actual != expected
    ):
        raise ControllerError("committed handoff drift")
    return {
        "ok": True,
        "operation": "verify",
        "mutated": False,
        "cycle_id": cycle["cycle_id"],
        "state": cycle["state"],
        "context_sha256": prepared.context_sha256,
        "artifact_sha256": cycle["artifact_sha256"],
        "actual_cost_usd": "0",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-spend readiness controller")
    parser.add_argument("operation", choices=ALLOWED_ACTIONS)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path("results/local/controller.sqlite"))
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--formula-approval", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/local/controller"))
    args = parser.parse_args()
    try:
        common = {
            "root": args.root,
            "config_path": args.config,
            "authority_path": args.authority,
            "formula_approval_path": args.formula_approval,
        }
        if args.operation == "status":
            result = controller_status(**common)
        elif args.operation == "prepare":
            result = controller_prepare(
                **common,
                db_path=args.db,
                output_dir=args.output_dir,
            )
        else:
            result = controller_verify(**common, db_path=args.db)
    except (ControllerError, DatabaseError, ValueError) as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        raise SystemExit(1) from exc
    emit(result)


if __name__ == "__main__":
    main()
