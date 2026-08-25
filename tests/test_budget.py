import json
from decimal import Decimal
from pathlib import Path

import pytest

from lowbit_lab.budget import BudgetError, BudgetGuard, ReferenceBudgetGuard

ROOT = Path(__file__).parents[1]


def test_phase_zero_allows_only_zero_spend() -> None:
    guard = BudgetGuard(ROOT / "configs/budget-policy.json")
    assert guard.authorize(phase=0, requested_cost_usd="0").requested == 0
    with pytest.raises(BudgetError, match="cap"):
        guard.authorize(phase=0, requested_cost_usd="0.01")
    assert guard.estimate_h100_cost(1, 3600) == 0


def test_single_job_and_total_ceiling_are_enforced() -> None:
    guard = BudgetGuard(ROOT / "configs/budget-policy.json")
    with pytest.raises(BudgetError, match="single-job"):
        guard.authorize(phase=4, requested_cost_usd="0.01")
    with pytest.raises(BudgetError, match="automated spend ceiling"):
        guard.authorize(phase=4, requested_cost_usd="0", total_spent_usd="0.01")


def test_price_is_validated(tmp_path: Path) -> None:
    raw = json.loads((ROOT / "configs/budget-policy.json").read_text(encoding="utf-8"))
    raw["h100_price_per_second"] = "not-money"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BudgetError, match="h100_price_per_second"):
        BudgetGuard(policy)


def test_frozen_ledger_cannot_be_raised(tmp_path: Path) -> None:
    raw = json.loads((ROOT / "configs/budget-policy.json").read_text(encoding="utf-8"))
    raw["automated_spend_ceiling"] = "1"
    raw["total_credits"] = "1"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(BudgetError, match="frozen zero-spend policy"):
        BudgetGuard(policy)


def _reference_policy(tmp_path: Path, **changes: object) -> Path:
    raw = {
        "schema_version": 1,
        "kind": "reference_budget_authority",
        "approved_plan_sha256": "a" * 64,
        "currency": "USD",
        "phase": 1,
        "phase_cap_usd": "4.00",
        "total_cap_usd": "4.00",
        "single_job_cap_usd": "4.00",
        "a100_80gb_price_per_second_usd": "0.000694",
        "cpu_core_price_per_second_usd": "0.0000131",
        "memory_gib_price_per_second_usd": "0.00000222",
        "submission_authorized": False,
    }
    raw.update(changes)
    path = tmp_path / "reference-budget.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_reference_budget_preview_is_exact_but_cannot_authorize_submission(
    tmp_path: Path,
) -> None:
    guard = ReferenceBudgetGuard(
        _reference_policy(tmp_path), expected_plan_sha256="a" * 64
    )
    preview = guard.preview(cpu_cores=8, memory_gib=96, wall_clock_seconds=2700)
    assert preview.estimated_cost_usd == Decimal("2.73218400")
    assert preview.local_reservation_limit_usd == Decimal("4.00")
    assert preview.submission_authorized is False
    with pytest.raises(BudgetError, match="not authorized"):
        guard.authorize_submission(requested_cost_usd="4.00")


def test_reference_budget_is_closed_and_bound_to_approved_plan(tmp_path: Path) -> None:
    with pytest.raises(BudgetError, match="plan hash"):
        ReferenceBudgetGuard(
            _reference_policy(tmp_path), expected_plan_sha256="b" * 64
        )
    with pytest.raises(BudgetError, match="closed"):
        ReferenceBudgetGuard(
            _reference_policy(tmp_path, extra=True), expected_plan_sha256="a" * 64
        )
    with pytest.raises(BudgetError, match="local reservation limit"):
        ReferenceBudgetGuard(
            _reference_policy(tmp_path, total_cap_usd="4.01"),
            expected_plan_sha256="a" * 64,
        )
