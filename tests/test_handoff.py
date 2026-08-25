from __future__ import annotations

import copy

import pytest

from lowbit_lab.handoff import (
    HandoffError,
    build_pre_spend_handoff,
    canonical_json,
    validate_pre_spend_handoff,
)


def _preview() -> dict[str, object]:
    return {
        "submit": False,
        "weights_transferred": False,
        "actual_cost_usd": "0",
        "challenge_sha256": "1" * 64,
        "config_sha256": "2" * 64,
        "reference_execution_scope_sha256": "3" * 64,
        "blockers": ["memory_fit_unproven", "cold_path_time_budget_unproven"],
    }


def _handoff() -> dict[str, object]:
    return build_pre_spend_handoff(
        preview=_preview(),
        reviewed_commit_sha256="4" * 40,
        control_plane_sha256="5" * 64,
        standing_authority_sha256="6" * 64,
        formula_approval_sha256="7" * 64,
        controller_context_sha256="8" * 64,
        configured_context_tokens=262144,
    )


def test_handoff_is_deterministic_and_stops_before_paid_action() -> None:
    first = _handoff()
    second = _handoff()

    assert canonical_json(first) == canonical_json(second)
    assert validate_pre_spend_handoff(first) == first
    assert first["paid_action_ready"] is False
    assert first["command_available"] is False
    assert first["budget"] == {
        "currency": "USD",
        "total_ledger_ceiling_usd": "0",
        "current_action_authorized_cap_usd": "0.00",
        "proposed_action_cap_usd": None,
        "requested_cost_usd": "0",
        "actual_cost_usd": "0",
    }
    assert first["context"] == {
        "configured_tokens": 262144,
        "configured": True,
        "usefulness_proven": False,
        "proven_useful_tokens": None,
    }
    assert first["required_approval_wording"] is None
    assert len(first["readiness_packet_sha256"]) == 64


def test_handoff_rejects_spend_or_cap_tampering() -> None:
    paid_preview = _preview()
    paid_preview["actual_cost_usd"] = "0.01"
    with pytest.raises(HandoffError, match="zero actual cost"):
        build_pre_spend_handoff(
            preview=paid_preview,
            reviewed_commit_sha256="4" * 40,
            control_plane_sha256="5" * 64,
            standing_authority_sha256="6" * 64,
            formula_approval_sha256="7" * 64,
            controller_context_sha256="8" * 64,
            configured_context_tokens=262144,
        )

    tampered = copy.deepcopy(_handoff())
    tampered["budget"]["current_action_authorized_cap_usd"] = "4.00"
    with pytest.raises(HandoffError, match="readiness packet mismatch"):
        validate_pre_spend_handoff(tampered)


def test_handoff_never_promotes_configured_context() -> None:
    tampered = copy.deepcopy(_handoff())
    tampered["context"]["usefulness_proven"] = True
    tampered["context"]["proven_useful_tokens"] = 262144
    with pytest.raises(HandoffError, match="readiness packet mismatch"):
        validate_pre_spend_handoff(tampered)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("lineage", "reviewed_commit_sha256", "a" * 40),
        ("lineage", "control_plane_sha256", "b" * 64),
        ("budget", "total_ledger_ceiling_usd", "1.00"),
        (None, "blockers", ["provider_adapter_unavailable"]),
        (None, "next_required_plan", "changed"),
    ],
)
def test_readiness_packet_binds_every_decision_field(
    section: str | None, field: str, replacement: object
) -> None:
    tampered = copy.deepcopy(_handoff())
    target = tampered if section is None else tampered[section]
    target[field] = replacement
    with pytest.raises(HandoffError, match="readiness packet mismatch"):
        validate_pre_spend_handoff(tampered)
