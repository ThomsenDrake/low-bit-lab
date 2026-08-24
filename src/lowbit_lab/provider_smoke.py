"""Closed contract and local gate for one no-weight Modal provider smoke action."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lowbit_lab.budget import BudgetError, ReferenceBudgetGuard
from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE
from lowbit_lab.db import DatabaseError, ResultsDatabase, confine_results_db
from lowbit_lab.handoff import canonical_json, sha256_json
from lowbit_lab.jsonio import emit

ACTION_KIND = "modal_provider_smoke"
ACTION_CAP_USD = "4.00"
APPROVAL_KIND = "modal_provider_smoke_approval"
IMPLEMENTATION_PLAN_SHA256 = "dd08a09dbdbd6e88f53a50de932fc15f933ee71d41a21f0f16ad28b68b402d61"
SMOKE_RESOURCE_SPEC = {
    "gpu": "A100-80GB:1",
    "cpu_cores": 8,
    "memory_mib": 96 * 1024,
    # Modal's per-container disk quota defaults to, and cannot be requested below, 512 GiB.
    "ephemeral_disk_mib": 512 * 1024,
    "timeout_seconds": 2700,
    "retries": 0,
    "max_containers": 1,
    "network_blocked": True,
    "secrets": [],
    "volumes": {},
    "schedule": None,
    "serialized_function": True,
}
SMOKE_RESOURCE_SHA256 = sha256_json(SMOKE_RESOURCE_SPEC)


class ProviderSmokeError(ValueError):
    pass


def _digest(value: object, label: str, *, revision: bool = False) -> str:
    pattern = IMMUTABLE_REVISION_RE if revision else SHA256_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProviderSmokeError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class ProviderSmokeContract:
    schema_version: int
    kind: str
    implementation_plan_sha256: str
    config_sha256: str
    challenge_sha256: str
    execution_scope_sha256: str
    reviewed_commit_sha256: str
    control_plane_sha256: str
    environment_scope_sha256: str
    provider_environment: str
    resource_envelope_sha256: str
    formula_approval_sha256: str
    billing_authority_sha256: str
    authoritative_report_identity_sha256: str
    billing_completeness_delay_seconds: int
    budget_authority_plan_sha256: str
    ledger_sha256: str
    maximum_cost_usd: str
    timeout_seconds: int
    weights_authorized: bool
    u8_authorized: bool
    approval_issued_at: str
    approval_expires_at: str
    action_contract_sha256: str


_CONTRACT_FIELDS = set(ProviderSmokeContract.__dataclass_fields__)


@dataclass(frozen=True)
class ProviderSmokeCapability:
    db_path: Path
    action_contract_sha256: str
    execution_scope_sha256: str
    reservation_id: str
    owner_id: str
    provider_environment: str


def build_contract(**values: Any) -> ProviderSmokeContract:
    if "execution_scope_sha256" in values:
        raise ProviderSmokeError("execution scope is derived from the action contract")
    material = {
        "schema_version": 1,
        "kind": ACTION_KIND,
        "implementation_plan_sha256": IMPLEMENTATION_PLAN_SHA256,
        **values,
        "maximum_cost_usd": ACTION_CAP_USD,
        "timeout_seconds": 2700,
        "weights_authorized": False,
        "u8_authorized": False,
    }
    material["execution_scope_sha256"] = sha256_json(material)
    material["action_contract_sha256"] = sha256_json(material)
    return validate_contract(material)


def validate_contract(value: object) -> ProviderSmokeContract:
    if not isinstance(value, dict) or set(value) != _CONTRACT_FIELDS:
        raise ProviderSmokeError("provider smoke contract schema is closed")
    material = {key: item for key, item in value.items() if key != "action_contract_sha256"}
    scope_material = {
        key: item for key, item in material.items() if key != "execution_scope_sha256"
    }
    if value.get("schema_version") != 1 or value.get("kind") != ACTION_KIND:
        raise ProviderSmokeError("unsupported provider smoke contract")
    for field in (
        "implementation_plan_sha256",
        "config_sha256",
        "challenge_sha256",
        "execution_scope_sha256",
        "control_plane_sha256",
        "environment_scope_sha256",
        "resource_envelope_sha256",
        "formula_approval_sha256",
        "billing_authority_sha256",
        "authoritative_report_identity_sha256",
        "budget_authority_plan_sha256",
        "ledger_sha256",
    ):
        _digest(value.get(field), field)
    _digest(value.get("reviewed_commit_sha256"), "reviewed_commit_sha256", revision=True)
    try:
        issued = datetime.fromisoformat(str(value.get("approval_issued_at")))
        expiry = datetime.fromisoformat(str(value.get("approval_expires_at")))
    except ValueError as exc:
        raise ProviderSmokeError("contract approval expiry is invalid") from exc
    if (
        value.get("implementation_plan_sha256") != IMPLEMENTATION_PLAN_SHA256
        or value.get("maximum_cost_usd") != ACTION_CAP_USD
        or value.get("timeout_seconds") != 2700
        or value.get("resource_envelope_sha256") != SMOKE_RESOURCE_SHA256
        or value.get("provider_environment") != "low-bit-lab"
        or value.get("billing_completeness_delay_seconds") != 3600
        or value.get("weights_authorized") is not False
        or value.get("u8_authorized") is not False
        or value.get("action_contract_sha256") != sha256_json(material)
        or value.get("execution_scope_sha256") != sha256_json(scope_material)
        or issued.tzinfo is None
        or expiry.tzinfo is None
        or expiry <= issued
        or expiry - issued > timedelta(minutes=30)
    ):
        raise ProviderSmokeError("provider smoke contract boundary changed")
    return ProviderSmokeContract(**value)


def _validate_live_lineage(
    contract: ProviderSmokeContract, *, root: Path, config_path: Path
) -> None:
    from lowbit_lab.modal_job import load_reference_job_config
    from lowbit_lab.runtime import runtime_metadata

    if config_path != Path("configs/local/reference.yaml"):
        raise ProviderSmokeError("provider smoke config path is fixed")
    config = load_reference_job_config(root / config_path, root=root)
    runtime = runtime_metadata(root)
    expected = {
        "config_sha256": config.sha256,
        "challenge_sha256": config.challenge_sha256,
        "reviewed_commit_sha256": config.inputs["reviewed_commit_sha256"],
        "control_plane_sha256": config.inputs["control_plane_sha256"],
        "environment_scope_sha256": config.provider["environment_scope_sha256"],
        "formula_approval_sha256": config.gates["formula_approval_sha256"],
        "billing_authority_sha256": config.provider["billing_authority_sha256"],
        "authoritative_report_identity_sha256": config.provider[
            "authoritative_report_identity_sha256"
        ],
    }
    if any(getattr(contract, key) != value for key, value in expected.items()):
        raise ProviderSmokeError("live provider smoke lineage does not match the contract")
    if (
        runtime["git_dirty"]
        or runtime["git_commit"] != contract.reviewed_commit_sha256
        or runtime["control_plane_sha256"] != contract.control_plane_sha256
    ):
        raise ProviderSmokeError("reviewed provider smoke runtime has drifted")


def build_live_contract(
    *,
    root: Path,
    config_path: Path,
    ledger_path: Path,
    approval_issued_at: str,
    approval_expires_at: str,
) -> ProviderSmokeContract:
    from lowbit_lab.modal_job import load_reference_job_config
    from lowbit_lab.runtime import runtime_metadata

    root = root.resolve()
    config = load_reference_job_config(root / config_path, root=root)
    runtime = runtime_metadata(root)
    if runtime["git_dirty"]:
        raise ProviderSmokeError("provider smoke contract requires a clean reviewed tree")
    try:
        ledger_bytes = (root / ledger_path).read_bytes()
        ledger_raw = json.loads(ledger_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderSmokeError(f"cannot read provider smoke ledger: {exc}") from exc
    contract = build_contract(
        config_sha256=config.sha256,
        challenge_sha256=config.challenge_sha256,
        reviewed_commit_sha256=runtime["git_commit"],
        control_plane_sha256=runtime["control_plane_sha256"],
        environment_scope_sha256=str(config.provider["environment_scope_sha256"]),
        provider_environment="low-bit-lab",
        resource_envelope_sha256=SMOKE_RESOURCE_SHA256,
        formula_approval_sha256=str(config.gates["formula_approval_sha256"]),
        billing_authority_sha256=str(config.provider["billing_authority_sha256"]),
        authoritative_report_identity_sha256=str(
            config.provider["authoritative_report_identity_sha256"]
        ),
        billing_completeness_delay_seconds=int(
            config.provider["billing_completeness_delay_seconds"]
        ),
        budget_authority_plan_sha256=str(ledger_raw.get("approved_plan_sha256")),
        ledger_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
        approval_issued_at=approval_issued_at,
        approval_expires_at=approval_expires_at,
    )
    _validate_live_lineage(contract, root=root, config_path=config_path)
    return contract


def approval_wording(contract: ProviderSmokeContract) -> str:
    return (
        "I approve one no-weight Modal provider smoke action for action contract SHA-256 "
        f"{contract.action_contract_sha256}, execution scope {contract.execution_scope_sha256}, "
        f"challenge {contract.challenge_sha256}, reviewed commit "
        f"{contract.reviewed_commit_sha256}, environment scope "
        f"{contract.environment_scope_sha256}, maximum authorized cost USD {ACTION_CAP_USD}, "
        f"timeout {SMOKE_RESOURCE_SPEC['timeout_seconds']} seconds, one A100-80GB GPU, "
        "no retries, no weights, no user payloads, no data or source mounts, "
        "no secrets, no volumes, no scheduling, and U8 remains unauthorized. "
        "Modal may receive only the audited function definition required for execution. "
        "I understand that the local reservation is not a provider-enforced hard dollar cap "
        "and accept residual provider-managed execution risk."
    )


def validate_approval(
    value: object, contract: ProviderSmokeContract, *, now: datetime | None = None
) -> str:
    fields = {
        "schema_version",
        "kind",
        "action_contract_sha256",
        "statement_sha256",
        "challenge_sha256",
        "execution_scope_sha256",
        "provider_environment",
        "reviewed_commit_sha256",
        "environment_scope_sha256",
        "maximum_cost_usd",
        "expires_at",
        "weights_authorized",
        "u8_authorized",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProviderSmokeError("provider smoke approval schema is closed")
    expected = {
        "schema_version": 1,
        "kind": APPROVAL_KIND,
        "action_contract_sha256": contract.action_contract_sha256,
        "statement_sha256": hashlib.sha256(approval_wording(contract).encode()).hexdigest(),
        "challenge_sha256": contract.challenge_sha256,
        "execution_scope_sha256": contract.execution_scope_sha256,
        "provider_environment": contract.provider_environment,
        "reviewed_commit_sha256": contract.reviewed_commit_sha256,
        "environment_scope_sha256": contract.environment_scope_sha256,
        "maximum_cost_usd": ACTION_CAP_USD,
        "weights_authorized": False,
        "u8_authorized": False,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise ProviderSmokeError("provider smoke approval does not match the action contract")
    try:
        expiry = datetime.fromisoformat(str(value["expires_at"]))
        contract_expiry = datetime.fromisoformat(contract.approval_expires_at)
    except ValueError as exc:
        raise ProviderSmokeError("provider smoke approval expiry is invalid") from exc
    current = now or datetime.now(UTC)
    issued = datetime.fromisoformat(contract.approval_issued_at)
    if issued > current:
        raise ProviderSmokeError("provider smoke approval is not yet valid")
    if expiry.tzinfo is None or expiry <= current:
        raise ProviderSmokeError("provider smoke approval is expired")
    if expiry != contract_expiry:
        raise ProviderSmokeError("provider smoke approval expiry does not match the contract")
    return sha256_json(value)


def load_contract(path: Path) -> ProviderSmokeContract:
    try:
        return validate_contract(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderSmokeError(f"cannot read provider smoke contract: {exc}") from exc


def _load_approval(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderSmokeError(f"cannot read provider smoke approval: {exc}") from exc


def execute(
    contract: ProviderSmokeContract,
    approval_path: Path,
    db_path: Path,
    ledger_path: Path,
    root: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Atomically consume approval and reserve the cap before importing the adapter."""
    if db_path != Path("results/local/reference.sqlite"):
        raise ProviderSmokeError("provider smoke database path is fixed")
    if ledger_path != Path("configs/local/reference-budget.json"):
        raise ProviderSmokeError("provider smoke ledger path is fixed")
    if approval_path != Path("configs/local/provider-smoke-approval.json"):
        raise ProviderSmokeError("provider smoke approval path is fixed")
    root = root.resolve()
    _validate_live_lineage(contract, root=root, config_path=config_path)
    resolved_db_path = confine_results_db(root, db_path)
    resolved_ledger_path = root / ledger_path
    approval = _load_approval(root / approval_path)
    approval_digest = validate_approval(approval, contract)
    try:
        ledger_sha256 = hashlib.sha256(resolved_ledger_path.read_bytes()).hexdigest()
        guard = ReferenceBudgetGuard(
            resolved_ledger_path,
            expected_plan_sha256=contract.budget_authority_plan_sha256,
        )
        guard.preview(
            cpu_cores=SMOKE_RESOURCE_SPEC["cpu_cores"],
            memory_gib=SMOKE_RESOURCE_SPEC["memory_mib"] // 1024,
            wall_clock_seconds=SMOKE_RESOURCE_SPEC["timeout_seconds"],
        )
        guard.authorize_submission(requested_cost_usd=ACTION_CAP_USD)
    except (OSError, BudgetError) as exc:
        raise ProviderSmokeError(f"provider smoke ledger is invalid: {exc}") from exc
    if ledger_sha256 != contract.ledger_sha256:
        raise ProviderSmokeError("provider smoke ledger does not match the contract")
    database = ResultsDatabase(resolved_db_path)
    database.initialize()
    reservation_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    occurred_at = datetime.now(UTC).isoformat()
    database.reserve_provider_smoke(
        reservation_id=reservation_id,
        action_contract_sha256=contract.action_contract_sha256,
        execution_scope_sha256=contract.execution_scope_sha256,
        challenge_sha256=contract.challenge_sha256,
        approval_json=canonical_json(approval),
        contract_json=canonical_json(asdict(contract)),
        owner_id=owner_id,
        occurred_at=occurred_at,
    )
    database.mark_provider_smoke_submission_pending(
        reservation_id, owner_id=owner_id, occurred_at=datetime.now(UTC).isoformat()
    )
    try:
        from lowbit_lab.modal_adapter import submit_provider_smoke

        result = submit_provider_smoke(
            ProviderSmokeCapability(
                db_path=resolved_db_path,
                action_contract_sha256=contract.action_contract_sha256,
                execution_scope_sha256=contract.execution_scope_sha256,
                reservation_id=reservation_id,
                owner_id=owner_id,
                provider_environment=contract.provider_environment,
            )
        )
    except Exception as exc:
        with suppress(DatabaseError):
            database.mark_provider_smoke_audit_blocked(
                reservation_id,
                owner_id=owner_id,
                reason=f"{type(exc).__name__}: provider state requires audit",
                occurred_at=datetime.now(UTC).isoformat(),
            )
        raise
    return {"approval_digest": approval_digest, "result": result}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gate one no-weight Modal provider smoke action")
    sub = parser.add_subparsers(dest="command", required=True)
    contract_parser = sub.add_parser("contract")
    contract_parser.add_argument("--root", type=Path, required=True)
    contract_parser.add_argument("--config", type=Path, required=True)
    contract_parser.add_argument("--ledger", type=Path, required=True)
    contract_parser.add_argument("--issued-at", required=True)
    contract_parser.add_argument("--expires-at", required=True)
    settle_parser = sub.add_parser("settle")
    settle_parser.add_argument("--root", type=Path, required=True)
    settle_parser.add_argument("--db", type=Path, required=True)
    settle_parser.add_argument("--report", type=Path, required=True)
    settle_parser.add_argument("--reservation-id", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--contract", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--contract", type=Path, required=True)
    verify.add_argument("--approval", type=Path, required=True)
    execute_parser = sub.add_parser("execute")
    execute_parser.add_argument("--contract", type=Path, required=True)
    execute_parser.add_argument("--approval", type=Path, required=True)
    execute_parser.add_argument("--db", type=Path, required=True)
    execute_parser.add_argument("--ledger", type=Path, required=True)
    execute_parser.add_argument("--confirm-scope", required=True)
    execute_parser.add_argument("--root", type=Path, required=True)
    execute_parser.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    command: str | None = None
    try:
        args = _parser().parse_args(argv)
        command = args.command
        if args.command == "settle":
            if args.db != Path("results/local/reference.sqlite") or args.report != Path(
                "reports/local/provider-smoke-billing.json"
            ):
                raise ProviderSmokeError("provider smoke settlement paths are fixed")
            root = args.root.resolve()
            db_path = confine_results_db(root, args.db)
            report_bytes = (root / args.report).read_bytes()
            report_json = report_bytes.decode("utf-8")
            database = ResultsDatabase(db_path)
            settlement = database.settle_provider_smoke(
                args.reservation_id,
                billing_report_json=report_json,
                billing_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
                occurred_at=datetime.now(UTC).isoformat(),
            )
            emit(
                {
                    "ok": True,
                    "command": "settle",
                    "provider_contacted": False,
                    **settlement,
                }
            )
            return 0
        if args.command == "contract":
            contract = build_live_contract(
                root=args.root,
                config_path=args.config,
                ledger_path=args.ledger,
                approval_issued_at=args.issued_at,
                approval_expires_at=args.expires_at,
            )
            emit({"ok": True, "command": "contract", "contract": asdict(contract)})
            return 0
        contract = load_contract(args.contract)
        result: dict[str, Any] = {
            "ok": True,
            "command": args.command,
            "action_contract_sha256": contract.action_contract_sha256,
            "maximum_cost_usd": ACTION_CAP_USD,
            "approval_wording": approval_wording(contract),
            "approval_expires_at": contract.approval_expires_at,
            "execution_scope_sha256": contract.execution_scope_sha256,
            "exact_execute_command": (
                "uv run --extra remote lowbit-paid-smoke execute "
                "--contract configs/local/provider-smoke-contract.json "
                "--approval configs/local/provider-smoke-approval.json "
                "--db results/local/reference.sqlite "
                "--ledger configs/local/reference-budget.json "
                "--root . --config configs/local/reference.yaml "
                f"--confirm-scope {contract.execution_scope_sha256}"
            ),
            "paid_action_ready": False,
            "provider_contacted": False,
        }
        if args.command == "verify":
            result["approval_digest"] = validate_approval(_load_approval(args.approval), contract)
        if args.command == "execute":
            if args.confirm_scope != contract.execution_scope_sha256:
                raise ProviderSmokeError("--confirm-scope must match the exact execution scope")
            result.update(
                execute(
                    contract,
                    args.approval,
                    args.db,
                    args.ledger,
                    args.root,
                    args.config,
                )
            )
            result["provider_contacted"] = True
            result.pop("paid_action_ready")
            result.pop("exact_execute_command")
        emit(result)
        return 0
    except (ProviderSmokeError, DatabaseError, BudgetError) as exc:
        emit(
            {
                "ok": False,
                "error": str(exc),
                "provider_contacted": "unknown" if command == "execute" else False,
            },
            stream=sys.stderr,
        )
        return 2
    except Exception:
        emit(
            {
                "ok": False,
                "error": "provider smoke failed; inspect the local audit record",
                "provider_contacted": "unknown" if command == "execute" else False,
            },
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
