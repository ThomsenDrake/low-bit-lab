import json
from pathlib import Path

import pytest

from lowbit_lab.budget import BudgetError, BudgetGuard

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
