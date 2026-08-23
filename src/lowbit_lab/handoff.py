from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE


class HandoffError(ValueError):
    pass


COMMAND_UNAVAILABLE_REASON = "provider_adapter_forbidden_by_controlling_plan"
NEXT_REQUIRED_PLAN = "paid_evidence_and_provider_adapter_amendment"
PAID_DECISION_BLOCKERS = {
    "cold_path_time_budget_unproven",
    "execution_approval_missing",
    "memory_fit_unproven",
    "provider_adapter_unavailable",
}


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _money(value: object, label: str) -> str:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError) as exc:
        raise HandoffError(f"{label} must be a decimal string") from exc
    if not isinstance(value, str) or not parsed.is_finite() or parsed < 0:
        raise HandoffError(f"{label} must be finite and non-negative")
    return value


def _decision_material(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "readiness_packet_sha256"}


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise HandoffError(f"{label} must be a lowercase SHA-256")
    return value


def build_pre_spend_handoff(
    *,
    preview: Mapping[str, Any],
    reviewed_commit_sha256: str,
    control_plane_sha256: str,
    standing_authority_sha256: str,
    formula_approval_sha256: str,
    controller_context_sha256: str,
    configured_context_tokens: int,
    total_ledger_ceiling_usd: str = "0",
) -> dict[str, Any]:
    """Build the timestamp-free, target-neutral handoff at the paid boundary."""
    if configured_context_tokens != 262144:
        raise HandoffError("configured_context_tokens must remain 262144")
    total_ledger_ceiling_usd = _money(
        total_ledger_ceiling_usd, "total_ledger_ceiling_usd"
    )
    if preview.get("submit") is not False or preview.get("weights_transferred") is not False:
        raise HandoffError("handoff requires a non-submitting, zero-transfer preview")
    if preview.get("actual_cost_usd") != "0":
        raise HandoffError("handoff requires zero actual cost")

    challenge = _digest(preview.get("challenge_sha256"), "challenge_sha256")
    config = _digest(preview.get("config_sha256"), "config_sha256")
    scope = _digest(
        preview.get("reference_execution_scope_sha256"),
        "reference_execution_scope_sha256",
        optional=True,
    )
    if IMMUTABLE_REVISION_RE.fullmatch(reviewed_commit_sha256) is None:
        raise HandoffError("reviewed_commit_sha256 must be an immutable revision")
    for label, value in (
        ("control_plane_sha256", control_plane_sha256),
        ("standing_authority_sha256", standing_authority_sha256),
        ("formula_approval_sha256", formula_approval_sha256),
        ("controller_context_sha256", controller_context_sha256),
    ):
        _digest(value, label)

    blockers = preview.get("blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise HandoffError("preview blockers must be a string list")
    blockers = sorted(set(blockers))
    if "provider_adapter_unavailable" not in blockers:
        blockers.append("provider_adapter_unavailable")
        blockers.sort()

    lineage = {
        "challenge_sha256": challenge,
        "config_sha256": config,
        "reference_execution_scope_sha256": scope,
        "reviewed_commit_sha256": reviewed_commit_sha256,
        "control_plane_sha256": control_plane_sha256,
        "standing_authority_sha256": standing_authority_sha256,
        "formula_approval_sha256": formula_approval_sha256,
        "controller_context_sha256": controller_context_sha256,
    }
    paid_decision_required = set(blockers).issubset(PAID_DECISION_BLOCKERS)
    satisfied_gates = sorted(
        {
            "formula_authority",
            "formula_approval_receipt",
            "standing_zero_spend_authority",
            "zero_spend_boundary",
        }
    )
    result = {
        "schema_version": 1,
        "kind": "pre_spend_handoff",
        "status": "paid_decision_required" if paid_decision_required else "stopped",
        "paid_action_ready": False,
        "command_available": False,
        "command": None,
        "command_unavailable_reason": COMMAND_UNAVAILABLE_REASON,
        "next_required_plan": NEXT_REQUIRED_PLAN,
        "readiness_packet_sha256": "",
        "required_approval_wording": None,
        "approval_wording_unavailable_reason": "exact_paid_action_contract_unavailable",
        "lineage": lineage,
        "budget": {
            "currency": "USD",
            "total_ledger_ceiling_usd": total_ledger_ceiling_usd,
            "current_action_authorized_cap_usd": "0.00",
            "proposed_action_cap_usd": None,
            "requested_cost_usd": "0",
            "actual_cost_usd": "0",
        },
        "safety": {
            "submit": False,
            "weights_transferred": False,
            "scheduling_enabled": False,
            "u8_authorized": False,
        },
        "context": {
            "configured_tokens": configured_context_tokens,
            "configured": True,
            "usefulness_proven": False,
            "proven_useful_tokens": None,
        },
        "satisfied_gates": satisfied_gates,
        "blockers": blockers,
    }
    result["readiness_packet_sha256"] = sha256_json(_decision_material(result))
    return result


def validate_pre_spend_handoff(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HandoffError("handoff must be an object")
    expected = {
        "schema_version",
        "kind",
        "status",
        "paid_action_ready",
        "command_available",
        "command",
        "command_unavailable_reason",
        "next_required_plan",
        "readiness_packet_sha256",
        "required_approval_wording",
        "approval_wording_unavailable_reason",
        "lineage",
        "budget",
        "safety",
        "context",
        "satisfied_gates",
        "blockers",
    }
    if set(value) != expected or value.get("schema_version") != 1:
        raise HandoffError("handoff schema is closed")
    if value.get("kind") != "pre_spend_handoff":
        raise HandoffError("unsupported handoff")
    packet_sha256 = _digest(value.get("readiness_packet_sha256"), "readiness_packet_sha256")
    if packet_sha256 != sha256_json(_decision_material(value)):
        raise HandoffError("readiness packet mismatch")
    if (
        value.get("status") not in {"paid_decision_required", "stopped"}
        or value.get("command_unavailable_reason") != COMMAND_UNAVAILABLE_REASON
        or value.get("next_required_plan") != NEXT_REQUIRED_PLAN
    ):
        raise HandoffError("handoff stop boundary changed")
    if value.get("paid_action_ready") is not False or value.get("command_available") is not False:
        raise HandoffError("paid action must remain unavailable")
    if value.get("command") is not None:
        raise HandoffError("paid command must be absent")
    if (
        value.get("required_approval_wording") is not None
        or value.get("approval_wording_unavailable_reason")
        != "exact_paid_action_contract_unavailable"
    ):
        raise HandoffError("approval wording must remain unavailable")
    budget = value.get("budget")
    safety = value.get("safety")
    context = value.get("context")
    if not isinstance(budget, dict) or set(budget) != {
        "currency",
        "total_ledger_ceiling_usd",
        "current_action_authorized_cap_usd",
        "proposed_action_cap_usd",
        "requested_cost_usd",
        "actual_cost_usd",
    }:
        raise HandoffError("handoff budget schema is closed")
    if (
        budget["currency"] != "USD"
        or _money(budget["total_ledger_ceiling_usd"], "total_ledger_ceiling_usd")
        != budget["total_ledger_ceiling_usd"]
        or budget["current_action_authorized_cap_usd"] != "0.00"
        or budget["proposed_action_cap_usd"] is not None
        or budget["requested_cost_usd"] != "0"
        or budget["actual_cost_usd"] != "0"
    ):
        raise HandoffError("handoff budget boundary changed")
    if not isinstance(safety, dict) or safety != {
        "submit": False,
        "weights_transferred": False,
        "scheduling_enabled": False,
        "u8_authorized": False,
    }:
        raise HandoffError("handoff safety boundary changed")
    if not isinstance(context, dict) or set(context) != {
        "configured_tokens",
        "configured",
        "usefulness_proven",
        "proven_useful_tokens",
    }:
        raise HandoffError("handoff context schema is closed")
    if context["configured"] is not True or context["usefulness_proven"] is not False:
        raise HandoffError("configured context cannot be reported as proven useful")
    if context["configured_tokens"] != 262144:
        raise HandoffError("configured context must remain 262144 tokens")
    if context["proven_useful_tokens"] is not None:
        raise HandoffError("proven useful context must remain unknown")
    lineage = value.get("lineage")
    if not isinstance(lineage, dict) or set(lineage) != {
        "challenge_sha256",
        "config_sha256",
        "reference_execution_scope_sha256",
        "reviewed_commit_sha256",
        "control_plane_sha256",
        "standing_authority_sha256",
        "formula_approval_sha256",
        "controller_context_sha256",
    }:
        raise HandoffError("handoff lineage schema is closed")
    for label, digest in lineage.items():
        if label == "reviewed_commit_sha256":
            if not isinstance(digest, str) or IMMUTABLE_REVISION_RE.fullmatch(digest) is None:
                raise HandoffError("reviewed_commit_sha256 must be an immutable revision")
            continue
        _digest(digest, label, optional=label == "reference_execution_scope_sha256")
    blockers = value.get("blockers")
    if (
        not isinstance(blockers, list)
        or not blockers
        or blockers != sorted(set(blockers))
        or any(not isinstance(item, str) or not item for item in blockers)
        or "provider_adapter_unavailable" not in blockers
    ):
        raise HandoffError("handoff blockers are invalid")
    if (value["status"] == "paid_decision_required") != set(blockers).issubset(
        PAID_DECISION_BLOCKERS
    ):
        raise HandoffError("handoff status does not match blockers")
    satisfied = value.get("satisfied_gates")
    if (
        not isinstance(satisfied, list)
        or satisfied != sorted(set(satisfied))
        or any(not isinstance(item, str) or not item for item in satisfied)
    ):
        raise HandoffError("satisfied gates are invalid")
    return value
